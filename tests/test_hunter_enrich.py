import asyncio
import datetime as dt
import json
import ssl

import httpx
import pytest

from hunter.config import load
from hunter.enrich.dns import DnsFailure, NxDomain, lookup_domain
from hunter.enrich.pipeline import EnrichContext, Enrichers, enrich_batch
from hunter.enrich.rdap import RdapClient
from hunter.enrich.tls import TlsEnricher, parse_certificate
from hunter.store import HuntStore
from investigation.storage import InvestigationStore
from watchtower.discovery.safe_fetch import UnsafeTarget

NOW = dt.datetime(2026, 9, 30, 12, 0, tzinfo=dt.timezone.utc)


def run(coro):
    return asyncio.run(coro)


class FakeDns:
    """table: (name, type) -> list | 'NX' | 'FAIL:reason'."""

    def __init__(self, table):
        self.table, self.calls = table, []

    async def __call__(self, name, rtype):
        self.calls.append((name, rtype))
        v = self.table.get((name, rtype), [])
        if v == "NX" or self.table.get((name, "*")) == "NX":
            raise NxDomain(name)
        if isinstance(v, str) and v.startswith("FAIL"):
            raise DnsFailure(v[5:])
        return v


# -- DNS ---------------------------------------------------------------------------------

def test_dns_resolved_records_and_ns_at_zone_apex():
    d = FakeDns({("login.mpesa-x.co.ke", "A"): ["203.0.113.9"], ("mpesa-x.co.ke", "NS"): ["ns1.host.example"]})
    r = run(lookup_domain("login.mpesa-x.co.ke", d))
    assert r.status == "resolved" and r.records["NS"] == ["ns1.host.example"] and r.complete
    assert ("mpesa-x.co.ke", "NS") in d.calls and ("login.mpesa-x.co.ke", "NS") not in d.calls


def test_dns_nxdomain_is_an_answer_and_skips_other_types():
    d = FakeDns({("gone-example.com", "*"): "NX"})
    r = run(lookup_domain("gone-example.com", d))
    assert r.status == "nxdomain" and d.calls == [("gone-example.com", "A")] and r.errors == {}


def test_dns_nodata_on_both_address_types_is_no_address():
    r = run(lookup_domain("parked-example.com", FakeDns({})))
    assert r.status == "no_address" and r.complete


def test_dns_servfail_is_an_error_not_an_empty_result():
    d = FakeDns({("a-example.com", "A"): "FAIL:SERVFAIL", ("a-example.com", "AAAA"): "FAIL:timeout"})
    r = run(lookup_domain("a-example.com", d))
    assert r.status == "error" and r.errors["A"] == "SERVFAIL" and not r.complete


def test_dns_partial_failure_keeps_answers_and_reports_incomplete():
    d = FakeDns({("a-example.com", "A"): ["203.0.113.9"], ("a-example.com", "AAAA"): "FAIL:timeout"})
    r = run(lookup_domain("a-example.com", d))
    assert r.status == "resolved" and not r.complete and "AAAA" in r.errors


def test_dns_a_failure_with_empty_aaaa_is_not_no_address():
    d = FakeDns({("a-example.com", "A"): "FAIL:timeout"})
    assert run(lookup_domain("a-example.com", d)).status == "error"


def test_dns_unexpected_resolver_exception_is_contained():
    async def boom(name, rtype):
        raise RuntimeError("kaput")
    r = run(lookup_domain("a-example.com", boom))
    assert r.status == "error" and "RuntimeError" in r.errors["A"]


def test_dns_non_public_answers_are_flagged_and_shared_hosting_skips_ns():
    d = FakeDns({("mpesa-x.vercel.app", "A"): ["10.0.0.5", "8.8.4.4"]})
    r = run(lookup_domain("mpesa-x.vercel.app", d))
    assert r.non_public_ips == ["10.0.0.5"] and not any(t == "NS" for _, t in d.calls)
    assert any("NS skipped" in n for n in r.notes)


def test_dns_facts_are_deterministic():
    a = run(lookup_domain("a-example.com", FakeDns({("a-example.com", "A"): ["1.1.1.1"]}))).facts()
    b = run(lookup_domain("a-example.com", FakeDns({("a-example.com", "A"): ["1.1.1.1"]}))).facts()
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


# -- RDAP --------------------------------------------------------------------------------

BOOTSTRAP = {"services": [[["com", "net", "xyz", "test"], ["https://rdap.example-registry.test/"]],
                          [["ke"], ["http://insecure.test/", "https://rdap.kenic.test/"]]]}


def rdap_record(**over):
    d = {"events": [{"eventAction": "registration", "eventDate": "2026-09-25T08:00:00Z"},
                    {"eventAction": "expiration", "eventDate": "2027-09-25T08:00:00Z"},
                    {"eventAction": "last changed", "eventDate": "2026-09-26T08:00:00Z"}],
         "status": ["client transfer prohibited"],
         "nameservers": [{"ldhName": "NS1.Cheap-Host.example"}, {"ldhName": "ns2.cheap-host.example"}],
         "entities": [
             {"roles": ["registrar"], "publicIds": [{"type": "IANA Registrar ID", "identifier": "1234"}],
              "vcardArray": ["vcard", [["fn", {}, "text", "Cheap Registrar LLC"]]]},
             {"roles": ["registrant"], "vcardArray": ["vcard", [
                 ["fn", {}, "text", "REDACTED FOR PRIVACY"], ["org", {}, "text", "Redacted"]]]}]}
    d.update(over)
    return d


def rdap_client(handler, store, **kw):
    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))

    async def nosleep(_):
        return None
    return RdapClient(http, store, min_interval=0, clock=lambda: NOW, sleep=nosleep, **kw)


def registry_handler(record=None, status=200, calls=None):
    def handler(request):
        if calls is not None:
            calls.append(str(request.url))
        if request.url.host == "data.iana.org":
            return httpx.Response(200, json=BOOTSTRAP)
        if status != 200:
            return httpx.Response(status, headers={"retry-after": "90"})
        return httpx.Response(200, json=rdap_record() if record is None else record)
    return handler


def test_rdap_parses_registration_registrar_and_redaction():
    store = HuntStore()
    calls = []
    r = run(rdap_client(registry_handler(calls=calls), store).lookup("www.mpesa-x.com"))
    assert r.status == "registered" and r.registrable == "mpesa-x.com"
    assert r.registered_at.startswith("2026-09-25") and r.registrar == "Cheap Registrar LLC"
    assert r.registrar_iana_id == "1234" and r.nameservers == ["ns1.cheap-host.example", "ns2.cheap-host.example"]
    assert r.registrant == {"redacted": True} and round(r.age_days(NOW), 1) == 5.2
    assert calls[-1] == "https://rdap.example-registry.test/domain/mpesa-x.com"


def test_rdap_two_part_suffix_and_https_service_preferred():
    calls = []
    run(rdap_client(registry_handler(calls=calls), HuntStore()).lookup("mpesa-x.co.ke"))
    assert calls[-1] == "https://rdap.kenic.test/domain/mpesa-x.co.ke"


def test_rdap_visible_registrant_is_flagged_personal_data():
    rec = rdap_record(entities=[{"roles": ["registrant"], "vcardArray": ["vcard", [
        ["org", {}, "text", "Acme Ltd"], ["email", {}, "text", "Boss@Acme.example"],
        ["adr", {}, "text", ["", "", "", "", "", "", "KE"]]]]}])
    r = run(rdap_client(registry_handler(rec), HuntStore()).lookup("acme-x.com"))
    assert r.registrant == {"redacted": False, "organization": "Acme Ltd", "country": "KE",
                            "email": "boss@acme.example", "personal_data": True}


def test_rdap_404_is_not_found_and_missing_fields_are_fine():
    r = run(rdap_client(registry_handler(status=404), HuntStore()).lookup("nope-x.com"))
    assert r.status == "not_found" and r.registered_at is None and r.age_days(NOW) is None
    sparse = run(rdap_client(registry_handler({}), HuntStore()).lookup("bare-x.com"))
    assert sparse.status == "registered" and sparse.registrar is None and sparse.registrant == {}


def test_rdap_unsupported_tld_and_shared_hosting():
    r = run(rdap_client(registry_handler(), HuntStore()).lookup("x-example.zz"))
    assert r.status == "unsupported"
    calls = []
    r = run(rdap_client(registry_handler(calls=calls), HuntStore()).lookup("mpesa-x.vercel.app"))
    assert r.status == "not_applicable" and calls == []


def test_rdap_429_cools_down_and_is_not_cached():
    store, calls = HuntStore(), []
    c = rdap_client(registry_handler(status=429, calls=calls), store)
    first = run(c.lookup("a-x.com"))
    assert first.status == "rate_limited" and first.retry_after >= 30
    n = len(calls)
    second = run(c.lookup("b-x.com"))
    assert second.status == "rate_limited" and len(calls) == n  # no request while cooling
    assert not any(k.startswith("rdap:domain") for k in store.get_state())


@pytest.mark.parametrize("bad", [httpx.Response(500), httpx.Response(200, text="<html>"),
                                 httpx.Response(200, json=["x"]), httpx.ConnectTimeout("slow")])
def test_rdap_failures_are_errors_never_registered_or_missing(bad):
    def handler(request):
        if request.url.host == "data.iana.org":
            return httpx.Response(200, json=BOOTSTRAP)
        if isinstance(bad, Exception):
            raise bad
        return bad
    store = HuntStore()
    r = run(rdap_client(handler, store).lookup("a-x.com"))
    assert r.status == "error" and r.error and not any(k.startswith("rdap:domain") for k in store.get_state())


def test_rdap_bootstrap_failure_is_an_error_not_unsupported():
    r = run(rdap_client(lambda req: httpx.Response(503), HuntStore()).lookup("a-x.com"))
    assert r.status == "error"


def test_rdap_caches_domain_and_bootstrap():
    store, calls = HuntStore(), []
    c = rdap_client(registry_handler(calls=calls), store, cache_hours=24)
    run(c.lookup("a-x.com"))
    n = len(calls)
    again = run(c.lookup("sub.a-x.com"))  # same registrable domain
    assert len(calls) == n and again.cached and again.status == "registered"
    run(c.lookup("b-x.com"))
    assert sum("data.iana.org" in u for u in calls) == 1


def test_rdap_refuses_redirect_to_internal_host():
    def handler(request):
        if request.url.host == "data.iana.org":
            return httpx.Response(200, json=BOOTSTRAP)
        return httpx.Response(302, headers={"location": "https://169.254.169.254/latest"})
    r = run(rdap_client(handler, HuntStore()).lookup("a-x.com"))
    assert r.status == "error" and "refusing" in r.error


# -- TLS ---------------------------------------------------------------------------------

def make_cert(names, tmp_path, days_valid=30):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0]),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Fake CA")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=days_valid))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
            .sign(key, hashes.SHA256()))
    pem, keyf = tmp_path / "c.pem", tmp_path / "k.pem"
    pem.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keyf.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                       serialization.NoEncryption()))
    return pem, keyf, cert


async def tls_server(pem, key):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(pem, key)

    async def handle(reader, writer):
        writer.close()
    server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=ctx)
    return server, server.sockets[0].getsockname()[1]


async def local(_host):
    return ["127.0.0.1"]  # tests reach a local server only by injecting the resolver


def test_tls_captures_self_signed_certificate_and_records_verification_failure(tmp_path):
    pem, key, cert = make_cert(["mpesa-x.test", "www.mpesa-x.test"], tmp_path)

    async def go():
        server, port = await tls_server(pem, key)
        async with server:
            return await TlsEnricher(3, port, resolver=local).fetch("mpesa-x.test")
    r = run(go())
    assert r.status == "ok" and r.verified is False and r.verification_error
    assert r.subject_cn == "mpesa-x.test" and r.sans == ["mpesa-x.test", "www.mpesa-x.test"]
    assert r.issuer == "Fake CA / mpesa-x.test" and len(r.fingerprint) == 64 and r.ip == "127.0.0.1"
    assert parse_certificate(cert.public_bytes(__import__("cryptography").hazmat.primitives.serialization.Encoding.DER))["subject_cn"] == "mpesa-x.test"


def test_tls_unreachable_port_is_a_recorded_answer():
    r = run(TlsEnricher(1, 1, resolver=local).fetch("mpesa-x.test"))
    assert r.status == "unreachable" and r.error


def test_tls_never_connects_to_non_public_addresses():
    calls = []

    async def resolver(host):
        raise UnsafeTarget("target resolves to a non-public address")

    async def handshake(*a):
        calls.append(a)
    r = run(TlsEnricher(1, resolver=resolver, handshake=handshake).fetch("evil.example"))
    assert r.status == "blocked" and calls == []

    async def nodns(host):
        raise UnsafeTarget("DNS resolution failed: nope")
    assert run(TlsEnricher(1, resolver=nodns).fetch("gone.example")).status == "unresolved"


def test_tls_real_resolver_blocks_loopback_names():
    assert run(TlsEnricher(1).fetch("localhost")).status == "blocked"


# -- pipeline ----------------------------------------------------------------------------

class FakeTls:
    def __init__(self, status="ok"):
        self.status, self.calls = status, []

    async def fetch(self, domain):
        from hunter.enrich.tls import TlsResult
        self.calls.append(domain)
        if self.status == "ok":
            import hashlib
            return TlsResult(domain, "ok", "203.0.113.9", hashlib.sha256(domain.encode()).hexdigest(), domain, "Fake CA", [domain],
                             "2026-09-29T00:00:00+00:00", "2026-12-29T00:00:00+00:00", True)
        return TlsResult(domain, self.status, error="refused")


class Harness:
    def __init__(self, dns, rdap_handler=None, tls=None, path=":memory:", **cfg_over):
        self.cfg = load("hunter.yaml")
        self.cfg.enrichment.concurrency = 1
        for k, v in cfg_over.items():
            setattr(self.cfg.enrichment, k, v)
        self.now = [NOW]
        self.store = HuntStore(path, clock=lambda: self.now[0])
        self.graph = InvestigationStore(path)
        self.tls = tls or FakeTls()
        self.rdap = rdap_client(rdap_handler or registry_handler(), self.store)
        self.ctx = EnrichContext(self.store, self.graph, self.cfg, {b.name: b for b in self.cfg.brands},
                                 Enrichers(FakeDns(dns), self.rdap, self.tls), clock=lambda: self.now[0])

    def add(self, domain, source="certificate_transparency", **kw):
        return self.store.submit(domain, source, brand="M-PESA", priority=kw.pop("priority", 60), **kw).candidate_id

    def batch(self, limit=10):
        return run(enrich_batch(self.ctx, limit))

    def evidence(self, cid, etype=None):
        rows = self.graph.conn.execute("SELECT * FROM evidence WHERE entity_id=?", (cid,)).fetchall()
        return [r for r in rows if etype is None or r["evidence_type"] == etype]


LIVE = {("mpesa-verify.xyz", "A"): ["203.0.113.9"], ("mpesa-verify.xyz", "NS"): ["ns1.cheap-host.example"]}


def rec_new():
    return rdap_record(events=[{"eventAction": "registration", "eventDate": "2026-09-28T00:00:00Z"}])


def test_strong_new_domain_goes_light_then_deep():
    h = Harness(LIVE, registry_handler(rec_new()))
    h.tls = h.ctx.en.tls
    cid = h.add("mpesa-verify.com", priority=10)
    h.ctx.en.dns_lookup.table.update({("mpesa-verify.com", "A"): ["203.0.113.9"]})
    s = h.batch()
    assert s.outcomes == {"queued_deep": 1}
    row = h.store.get(cid)
    assert row["status"] == "QUEUED" and row["stage"] == "light" and row["priority"] > 55  # rescored from age 2d
    assert h.tls.calls == []                                            # no TLS on the light pass
    s2 = h.batch()
    assert s2.outcomes == {"deep": 1} and h.tls.calls == ["mpesa-verify.com"]
    row = h.store.get(cid)
    assert (row["status"], row["stage"]) == ("SCORED", "deep") and row["risk_score"] is not None
    types = {e["evidence_type"] for e in h.evidence(cid)}
    assert {"dns_lookup", "rdap_lookup", "tls_lookup"} <= types
    rels = {r["relationship_type"] for r in h.graph.conn.execute("SELECT * FROM relationships").fetchall()}
    assert {"resolves_to", "uses_nameserver", "registered_with", "uses_certificate"} <= rels
    assert [x["event"] for x in h.store.history(cid) if x["event"] == "deep_started"] == ["deep_started"]


def test_weak_candidate_stops_after_light_pass():
    h = Harness({("mpesa.somewhere.com", "A"): ["203.0.113.9"]}, registry_handler(rdap_record()))
    cid = h.add("mpesa.somewhere.com", priority=40)
    assert h.batch().outcomes == {"light": 1}
    row = h.store.get(cid)
    assert (row["status"], row["stage"]) == ("SCORED", "light") and h.tls.calls == []


def test_unregistered_name_is_rechecked_on_a_schedule_then_ignored():
    h = Harness({("mpesa-loan.xyz", "*"): "NX"}, registry_handler(status=404),
                unregistered_recheck_days=[1, 3])
    cid = h.add("mpesa-loan.xyz", "permutation")
    assert h.batch().outcomes == {"deferred_unregistered": 1}
    row = h.store.get(cid)
    assert row["status"] == "QUEUED" and "not registered" in row["deferred_reason"] and row["attempts"] == 0
    assert h.batch().claimed == 0                                       # not due yet
    h.now[0] += dt.timedelta(days=1, minutes=1)
    assert h.batch().outcomes == {"deferred_unregistered": 1}
    h.now[0] += dt.timedelta(days=3, minutes=1)
    assert h.batch().outcomes == {"ignored_unregistered": 1}
    row = h.store.get(cid)
    assert row["status"] == "IGNORED"
    assert "still not resolving after 2 re-checks" in [x for x in h.store.history(cid)][-1]["detail"]
    assert h.evidence(cid, "dns_lookup") and h.evidence(cid, "rdap_lookup")  # the absence is on the record
    h.store.requeue(cid, reason="analyst look again")                         # and can be revived
    assert h.store.get(cid)["status"] == "QUEUED"


def test_nxdomain_with_rdap_unavailable_says_registration_unverified():
    h = Harness({("mpesa-loan.zz", "*"): "NX"})
    cid = h.add("mpesa-loan.zz", "permutation")
    h.batch()
    assert "registration unverified: RDAP unsupported" in h.store.get(cid)["deferred_reason"]


def test_dns_servfail_fails_the_candidate_for_retry_never_clean():
    h = Harness({("mpesa-verify.com", "A"): "FAIL:SERVFAIL", ("mpesa-verify.com", "AAAA"): "FAIL:SERVFAIL"})
    cid = h.add("mpesa-verify.com")
    assert h.batch().outcomes == {"failed_retry": 1}
    row = h.store.get(cid)
    assert row["status"] == "RETRY" and "DNS lookup failed" in row["error_state"]
    assert h.evidence(cid, "dns_lookup")                                # what we did learn is still saved


def test_rdap_error_retries_and_rdap_rate_limit_defers_with_reason():
    h = Harness(LIVE, registry_handler(status=500))
    h.add("mpesa-verify.xyz")
    assert h.batch().outcomes == {"failed_retry": 1}
    h2 = Harness(LIVE, registry_handler(status=429))
    cid2 = h2.add("mpesa-verify.xyz")
    assert h2.batch().outcomes == {"deferred_rate_limit": 1}
    row = h2.store.get(cid2)
    assert row["status"] == "QUEUED" and "RDAP rate limited" in row["deferred_reason"] and row["attempts"] == 0


def test_deep_budget_defers_with_reason_and_frees_after_the_hour():
    h = Harness({("mpesa-verify.com", "A"): ["203.0.113.9"]}, registry_handler(rec_new()), max_deep_per_hour=1)
    ids = [h.add(f"mpesa-verify{i}.com" if i else "mpesa-verify.com", priority=50 + i) for i in range(2)]
    h.ctx.en.dns_lookup.table.update({("mpesa-verify1.com", "A"): ["203.0.113.10"]})
    h.batch(); h.batch()                                              # light passes
    h.batch(5)                                                         # first deep runs, second is over budget
    states = {i: h.store.get(i) for i in ids}
    assert sorted(s["stage"] for s in states.values()) == ["deep", "light"]
    waiting = next(s for s in states.values() if s["stage"] == "light")
    assert waiting["status"] == "QUEUED" and "budget reached (1/hour)" in waiting["deferred_reason"]
    assert h.store.stats()["deferred"] == 1
    h.now[0] += dt.timedelta(hours=1, minutes=1)
    assert h.batch(5).outcomes == {"deep": 1}


def test_non_domain_candidates_are_completed_with_an_explicit_note():
    h = Harness({})
    cid = h.store.submit("https://x-example.com/some/page", "page", brand="M-PESA").candidate_id
    assert h.batch().outcomes == {"unsupported_type": 1}
    assert "no enrichers defined for indicator type url" in h.store.history(cid)[-1]["detail"]


def test_identical_answers_dedupe_and_changed_answers_add_history():
    h = Harness({("mpesa.somewhere.com", "A"): ["203.0.113.9"]})
    cid = h.add("mpesa.somewhere.com", priority=40)
    h.batch()
    n = len(h.evidence(cid, "dns_lookup"))
    h.store.requeue(cid, stage="none")
    h.batch()
    assert len(h.evidence(cid, "dns_lookup")) == n                    # unchanged: no duplicate row
    h.ctx.en.dns_lookup.table[("mpesa.somewhere.com", "A")] = ["203.0.113.77"]
    h.store.requeue(cid, stage="none")
    h.batch()
    values = [json.loads(e["observed_value"])["records"]["A"] for e in h.evidence(cid, "dns_lookup")]
    assert ["203.0.113.9"] in values and ["203.0.113.77"] in values   # both kept


def test_provider_stats_are_recorded_per_batch():
    h = Harness(LIVE, registry_handler(status=500))
    h.add("mpesa-verify.xyz")
    h.batch()
    health = {p["provider"]: p for p in h.store.provider_health()}
    assert health["rdap"]["status"] == "provider_error" and health["rdap"]["consecutive_failures"] == 1
    assert health["dns"]["status"] == "operational"


def test_batch_survives_one_candidate_blowing_up():
    h = Harness({("mpesa.somewhere.com", "A"): ["203.0.113.9"]})
    ok = h.add("mpesa.somewhere.com", priority=40)
    bad = h.add("mpesa-boom.com", priority=90)

    async def boom(domain):
        raise RuntimeError("kaput")
    real = h.rdap.lookup

    async def picky(domain):
        return await boom(domain) if "boom" in domain else await real(domain)
    h.rdap.lookup = picky
    s = h.batch()
    assert s.outcomes == {"failed_retry": 1, "light": 1}
    assert h.store.get(bad)["status"] == "RETRY" and h.store.get(ok)["status"] == "SCORED"


def test_one_investigation_holds_all_hunter_evidence():
    h = Harness({("mpesa.somewhere.com", "A"): ["203.0.113.9"]})
    h.add("mpesa.somewhere.com", priority=40)
    h.add("mpesa.elsewhere.com", priority=40)
    h.ctx.en.dns_lookup.table[("mpesa.elsewhere.com", "A")] = ["203.0.113.9"]
    h.batch()
    inv = {r["investigation_id"] for r in h.graph.conn.execute("SELECT investigation_id FROM evidence")}
    assert len(inv) == 1
    ips = h.graph.conn.execute("SELECT COUNT(*) FROM entities WHERE entity_type='ip_address'").fetchone()[0]
    assert ips == 1                                                     # shared IP is one node, ready for correlation


# -- page capture inside the deep stage ----------------------------------------------------

from hunter.acquire import Page, SiteCapture  # noqa: E402


class FakeAcquire:
    def __init__(self, cap):
        self.cap, self.calls = cap, []

    async def capture(self, domain):
        self.calls.append(domain)
        return self.cap(domain) if callable(self.cap) else self.cap

    async def close(self):
        return None


def good_page(url="https://mpesa-verify.com/", **kw):
    base = dict(requested_url=url, final_url=url, status=200, content_type="text/html", analyzable=True,
                title="M-PESA Verify", visible_text="Enter your PIN and OTP", body_sha256="ab" * 32, body_bytes=900,
                forms=[{"action": "/v", "method": "post", "inputs": [{"name": "pin", "type": "password"}]}],
                links=["https://wa.me/254700000000"], robots={"verdict": "allowed", "status": "no_robots"})
    base.update(kw)
    return Page(**base)


def deep_harness(acquire, dns=None):
    h = Harness({("mpesa-verify.com", "A"): ["8.8.8.8"]} if dns is None else dns, registry_handler(rec_new()))
    h.ctx.en.acquire = acquire
    cid = h.add("mpesa-verify.com")
    h.store.conn.execute("UPDATE hunt_candidates SET stage='light' WHERE id=?", (cid,))
    return h, cid


def test_deep_stage_captures_the_site_and_stores_page_evidence():
    acq = FakeAcquire(lambda d: SiteCapture(d, [good_page(), good_page("https://mpesa-verify.com/login", title="Login")]))
    h, cid = deep_harness(acq)
    assert h.batch().outcomes == {"deep": 1} and acq.calls == ["mpesa-verify.com"]
    http = h.evidence(cid, "http_response")
    assert len(http) == 2
    facts = json.loads(http[0]["observed_value"])
    assert facts["title"] == "M-PESA Verify" and facts["forms"][0]["fields"][0]["name"] == "pin"
    assert facts["robots"]["verdict"] == "allowed" and facts["js_rendering"] == "not_available"
    snap = h.evidence(cid, "page_text")
    assert snap and snap[0]["observed_value"] == "Enter your PIN and OTP"
    assert json.loads(snap[0]["raw_metadata"])["personal_data"] is True
    assert "page 200 +1 pages" in h.store.history(cid)[-1]["detail"]
    assert h.ctx.stats["http"].ok == 1


def test_cross_site_redirect_and_meta_refresh_become_relationships():
    page = good_page(final_url="https://landing-elsewhere.com/go", meta_refresh="https://third-site.com/x",
                     redirect_chain=["https://mpesa-verify.com/", "https://landing-elsewhere.com/go"])
    h, cid = deep_harness(FakeAcquire(SiteCapture("mpesa-verify.com", [page])))
    h.batch()
    rows = h.graph.conn.execute("""SELECT e.canonical_value, r.relationship_type, r.confidence FROM relationships r
        JOIN entities e ON e.id=r.target_entity_id WHERE r.relationship_type='redirects_to'""").fetchall()
    assert {(r[0], r[2]) for r in rows} == {("landing-elsewhere.com", 0.95), ("third-site.com", 0.6)}


def test_same_registrable_redirect_is_not_a_new_relationship():
    page = good_page(final_url="https://www.mpesa-verify.com/home")
    h, _ = deep_harness(FakeAcquire(SiteCapture("mpesa-verify.com", [page])))
    h.batch()
    assert h.graph.conn.execute("SELECT COUNT(*) FROM relationships WHERE relationship_type='redirects_to'").fetchone()[0] == 0


def test_failed_page_attempts_are_recorded_as_evidence_not_dropped():
    dead = Page("https://mpesa-verify.com/", error="ConnectError: refused", error_kind="unreachable")
    alive = good_page("http://mpesa-verify.com/")
    h, cid = deep_harness(FakeAcquire(SiteCapture("mpesa-verify.com", [alive], [dead], ["https unreachable; trying http"])))
    h.batch()
    kinds = sorted(json.loads(e["observed_value"])["error_kind"] or "ok" for e in h.evidence(cid, "http_response"))
    assert kinds == ["ok", "unreachable"]


def test_blocked_landing_is_a_recorded_fact_not_a_candidate_failure():
    blocked = Page("https://mpesa-verify.com/", error="target resolves to a non-public address", error_kind="blocked")
    h, cid = deep_harness(FakeAcquire(SiteCapture("mpesa-verify.com", [blocked])))
    assert h.batch().outcomes == {"deep": 1}
    assert "page blocked" in h.store.history(cid)[-1]["detail"]


def test_no_page_fetch_without_a_usable_address():
    acq = FakeAcquire(SiteCapture("x", []))
    h, cid = deep_harness(acq, {("mpesa-verify.com", "A"): ["10.0.0.5"]})
    assert h.batch().outcomes == {"deep": 1} and acq.calls == []
    assert "every address is non-public" in h.store.history(cid)[-1]["detail"]
    acq2 = FakeAcquire(SiteCapture("x", []))
    h2, cid2 = deep_harness(acq2, {})
    h2.batch()
    assert acq2.calls == [] and "dns no_address" in h2.store.history(cid2)[-1]["detail"]


def test_acquisition_crash_retries_the_candidate():
    async def boom(domain):
        raise RuntimeError("kaput")
    acq = FakeAcquire(None)
    acq.capture = boom
    h, cid = deep_harness(acq)
    assert h.batch().outcomes == {"failed_retry": 1}
    assert h.store.get(cid)["status"] == "RETRY" and h.ctx.stats["http"].failed == 1


def test_enrichment_without_acquirer_still_works():
    h, cid = deep_harness(None)
    assert h.batch().outcomes == {"deep": 1}


# -- signals inside the deep stage ---------------------------------------------------------------------

from pathlib import Path  # noqa: E402

_FIX = Path(__file__).parent / "fixtures"


def html_page(name, url, **kw):
    from watchtower.discovery.page_analysis import analyze_page
    text = (_FIX / name).read_text()
    p = good_page(url, **kw)
    p.html, p.visible_text = text, analyze_page(text, url).visible_text
    return p


def entity_rows(h, etype):
    return [r["canonical_value"] for r in h.graph.conn.execute("SELECT * FROM entities WHERE entity_type=?", (etype,))]


def test_deep_stage_extracts_indicators_into_the_graph_with_provenance():
    page = html_page("phishing_login.html", "https://mpesa-verify.com/")
    h, cid = deep_harness(FakeAcquire(SiteCapture("mpesa-verify.com", [page])))
    h.batch()
    assert "+254700000001" in entity_rows(h, "whatsapp") and "collector.example" in entity_rows(h, "domain")
    rels = {(r["relationship_type"]) for r in h.graph.conn.execute("SELECT * FROM relationships")}
    assert {"uses_whatsapp", "links_to", "uses_analytics_id"} <= rels
    ev = [e for e in h.evidence("whatsapp:" + "x", "x")]  # sanity: helper tolerates unknown ids
    assert ev == []
    row = h.graph.conn.execute("SELECT * FROM evidence WHERE evidence_type='extracted_indicator' AND observed_value='+254700000001'").fetchone()
    meta = json.loads(row["raw_metadata"])
    assert meta["where"] == ["link"] and meta["found_on"] == "mpesa-verify.com" and meta["personal_data"] is True
    assert row["source_url"] == "https://mpesa-verify.com/" and row["confidence"] == 0.95
    sig_ev = h.evidence(cid, "page_signals")[0]
    flags = json.loads(sig_ev["observed_value"])["flags"]
    assert flags["credential_form"] and flags["cross_origin_form"] and flags["whatsapp_cta"]
    assert "credential_form" in json.loads(sig_ev["raw_metadata"])["flags_true"]
    assert "signals:" in h.store.history(cid)[-1]["detail"] and "credential_form" in h.store.history(cid)[-1]["detail"]


def test_shared_whatsapp_number_is_one_node_linked_from_two_domains():
    a = html_page("phishing_login.html", "https://mpesa-verify.com/")
    h, cid_a = deep_harness(FakeAcquire(lambda d: SiteCapture(d, [html_page("phishing_login.html", f"https://{d}/")])))
    cid_b = h.add("mpesa-second.com")
    h.store.conn.execute("UPDATE hunt_candidates SET stage='light' WHERE id=?", (cid_b,))
    h.ctx.en.dns_lookup.table[("mpesa-second.com", "A")] = ["8.8.4.4"]
    h.batch(5)
    nodes = h.graph.conn.execute("SELECT id FROM entities WHERE entity_type='whatsapp'").fetchall()
    assert len(nodes) == 1
    linked = {r["source_entity_id"] for r in h.graph.conn.execute(
        "SELECT * FROM relationships WHERE relationship_type='uses_whatsapp' AND target_entity_id=?", (nodes[0]["id"],))}
    assert linked == {cid_a, cid_b} and a.html != ""


def test_market_is_estimated_stored_and_explained():
    page = html_page("fake_investment.html", "https://mpesa-verify.com/")
    h, cid = deep_harness(FakeAcquire(SiteCapture("mpesa-verify.com", [page])))
    h.batch()
    row = h.store.get(cid)
    assert row["market"] == "Kenya" and row["market_confidence"] > 0.5
    est = json.loads(h.evidence(cid, "market_estimate")[0]["observed_value"])
    assert est["market"] == "Kenya" and {e["signal"] for e in est["evidence"]} >= {"phone_country_code", "currency"}
    assert "market Kenya" in h.store.history(cid)[-1]["detail"]


def test_raw_html_is_dropped_after_extraction_and_never_stored():
    page = html_page("phishing_login.html", "https://mpesa-verify.com/")
    h, cid = deep_harness(FakeAcquire(SiteCapture("mpesa-verify.com", [page])))
    h.batch()
    assert page.html == ""
    blob = " ".join(r["observed_value"] for r in h.graph.conn.execute("SELECT observed_value FROM evidence"))
    assert "<form" not in blob and "abc123" not in blob


def test_advisory_page_is_flagged_so_its_quoted_indicators_can_be_discounted():
    page = html_page("security_report.html", "https://mpesa-verify.com/")
    h, cid = deep_harness(FakeAcquire(SiteCapture("mpesa-verify.com", [page])))
    h.batch()
    flags = json.loads(h.evidence(cid, "page_signals")[0]["observed_value"])["flags"]
    assert flags["advisory_context"] and not flags["credential_form"] and not flags["credential_language"]
    assert "+254700000099" in entity_rows(h, "whatsapp") + entity_rows(h, "phone_number")   # still recorded as sightings


def test_extraction_failure_on_one_page_does_not_lose_the_others(monkeypatch):
    import hunter.enrich.pipeline as pl
    real = pl.extract_signals
    calls = []

    def flaky(page, brand, cfg):
        calls.append(page.requested_url)
        if "login" in page.requested_url:
            raise RuntimeError("parser exploded")
        return real(page, brand, cfg)
    monkeypatch.setattr(pl, "extract_signals", flaky)
    good = html_page("fake_investment.html", "https://mpesa-verify.com/")
    bad = html_page("phishing_login.html", "https://mpesa-verify.com/login")
    h, cid = deep_harness(FakeAcquire(SiteCapture("mpesa-verify.com", [good, bad])))
    assert h.batch().outcomes == {"failed_retry": 1}                  # surfaced for retry, not swallowed
    assert h.store.get(cid)["status"] == "RETRY" and "parser exploded" in h.store.get(cid)["error_state"]


def test_unassessed_page_is_recorded_loudly_in_evidence_and_note():
    page = html_page("phishing_login.html", "https://mpesa-verify.com/")
    page.unassessed_reason = "HTTP 403 (bot challenge)"
    h, cid = deep_harness(FakeAcquire(SiteCapture("mpesa-verify.com", [page])))
    h.batch()
    assert "UNASSESSED (HTTP 403 (bot challenge))" in h.store.history(cid)[-1]["detail"]
    facts = json.loads(h.evidence(cid, "page_signals")[0]["observed_value"])
    assert facts["flags"]["content_unassessed"] and facts["unassessed_reason"] == "HTTP 403 (bot challenge)"
    assert json.loads(h.evidence(cid, "http_response")[0]["observed_value"])["unassessed_reason"]
