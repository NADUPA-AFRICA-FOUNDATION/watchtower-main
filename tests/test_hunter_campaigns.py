import json

import pytest

from hunter.config import ConfigError, parse
from hunter.graphq import GraphQueries
from hunter.scoring import rescore, rescore_and_route
from investigation.models import Entity, Evidence, Relationship
from test_hunter_enrich import FakeAcquire, Harness, SiteCapture, registry_handler
from test_hunter_scoring import NEW, fx


class Net:
    """Builds graph facts directly, so link rules can be tested without fetching anything."""

    def __init__(self, **cfg_over):
        self.h = Harness({}, registry_handler(NEW))
        for k, v in cfg_over.items():
            setattr(self.h.cfg.correlation, k, v)
        self.iid = self.h.ctx.investigation_id("M-PESA")
        self.cor = self.h.ctx.correlator
        self.ids = {}

    def domain(self, name):
        if name not in self.ids:
            self.ids[name] = self.h.add(name)
            self.h.graph.persist(self.iid, [Entity("domain", name, name)], [], [])
        return self.ids[name]

    def link(self, domain, node_type, value, rel="uses_phone", where=None):
        d = Entity("domain", domain, domain)
        n = Entity(node_type, value, value)
        ev = Evidence(self.iid, n.id, "signals", "extracted_indicator", value, f"https://{domain}/",
                      {"where": where or ["link"], "found_on": domain})
        self.h.graph.persist(self.iid, [d, n], [ev], [Relationship(self.iid, d.id, n.id, rel, 0.9, ev.id)])
        self.domain(domain)
        return ev.id

    def clusters(self, domain):
        return self.cor.clusters_for(self.domain(domain))

    def run(self, domain):
        return self.cor.update_for(self.domain(domain), "M-PESA", self.iid)

    def campaigns(self):
        return [dict(r) for r in self.h.graph.conn.execute("SELECT * FROM campaigns ORDER BY created_at, id")]


# -- link strength rules ---------------------------------------------------------------------------------------------

def test_a_shared_whatsapp_number_is_a_strong_link_and_forms_a_campaign():
    n = Net()
    n.link("mpesa-a.com", "whatsapp", "+254700000001", "uses_whatsapp")
    n.link("mpesa-b.com", "whatsapp", "+254700000001", "uses_whatsapp")
    (c,) = n.clusters("mpesa-a.com")
    assert sorted(c.names.values()) == ["mpesa-a.com", "mpesa-b.com"] and c.confidence >= 0.7
    (link,) = next(iter(c.pairs.values()))
    assert (link.name, link.strength, link.users) == ("shares_phone", "strong", 2)


def test_a_number_is_one_identity_across_phone_and_whatsapp_types():
    n = Net()
    n.link("mpesa-a.com", "whatsapp", "+254700000001", "uses_whatsapp")
    n.link("mpesa-b.com", "phone_number", "+254700000001", "uses_phone")
    assert len(n.clusters("mpesa-a.com")) == 1


@pytest.mark.parametrize("node_type,value,rel,name", [
    ("telegram", "mpesa_help", "uses_telegram", "shares_telegram"),
    ("payment_identifier", "paybill:123456", "uses_payment_identifier", "shares_payment_identifier"),
    ("crypto_wallet", "btc:bc1qxxxx", "uses_crypto_wallet", "shares_crypto_wallet"),
    ("analytics_id", "google_analytics:g-abc", "uses_analytics_id", "shares_analytics_id"),
    ("email", "scammer@gmail.com", "uses_email", "shares_email"),
    ("html_fingerprint", "sha256:abc", "uses_html_fingerprint", "shares_html_fingerprint"),
])
def test_every_strong_node_type_links_two_domains(node_type, value, rel, name):
    n = Net()
    n.link("mpesa-a.com", node_type, value, rel)
    n.link("mpesa-b.com", node_type, value, rel)
    (c,) = n.clusters("mpesa-a.com")
    assert next(iter(c.pairs.values()))[0].name == name


def test_two_sites_posting_credentials_to_one_collector_are_strongly_linked_but_a_shared_link_target_is_not():
    n = Net()
    n.link("mpesa-a.com", "domain", "collector.example", "links_to", ["form_action"])
    n.link("mpesa-b.com", "domain", "collector.example", "links_to", ["form_action"])
    (c,) = n.clusters("mpesa-a.com")
    assert next(iter(c.pairs.values()))[0].name == "shares_form_endpoint"
    n2 = Net()
    n2.link("mpesa-a.com", "domain", "popular-site.example", "links_to", ["link"])
    n2.link("mpesa-b.com", "domain", "popular-site.example", "links_to", ["link"])
    assert n2.clusters("mpesa-a.com") == []


def test_weak_links_never_make_a_campaign_however_many_there_are():
    n = Net()
    for d in ("mpesa-a.com", "mpesa-b.com"):
        n.link(d, "registrar", "cheap registrar llc", "registered_with")
        n.link(d, "ip_address", "104.21.5.5", "resolves_to")                       # Cloudflare range
        n.link(d, "nameserver", "kim.ns.cloudflare.com", "uses_nameserver")        # mass-market DNS
        n.link(d, "domain", "popular-site.example", "links_to")
    assert n.clusters("mpesa-a.com") == [] and n.run("mpesa-a.com") == [] and n.campaigns() == []


def test_one_medium_link_is_not_enough_two_independent_ones_are():
    n = Net()
    n.link("mpesa-a.com", "ip_address", "8.8.8.8", "resolves_to")
    n.link("mpesa-b.com", "ip_address", "8.8.8.8", "resolves_to")
    assert n.clusters("mpesa-a.com") == []
    n.link("mpesa-a.com", "nameserver", "ns1.small-host.example", "uses_nameserver")
    n.link("mpesa-b.com", "nameserver", "ns1.small-host.example", "uses_nameserver")
    (c,) = n.clusters("mpesa-a.com")
    assert {l.name for l in next(iter(c.pairs.values()))} == {"shares_ip", "shares_nameserver"}
    assert 0.5 <= c.confidence < 0.8                                               # medium evidence is not strong confidence


def test_a_certificate_a_redirect_target_and_a_social_profile_are_medium():
    n = Net()
    for d in ("mpesa-a.com", "mpesa-b.com"):
        n.link(d, "certificate", "sha256:abc", "uses_certificate")
        n.link(d, "domain", "hop.example", "redirects_to", ["redirect"])
    (c,) = n.clusters("mpesa-a.com")
    assert {(l.name, l.strength) for l in next(iter(c.pairs.values()))} == {("shares_certificate", "medium"), ("shares_redirect_target", "medium")}


def test_a_direct_redirect_between_two_investigated_domains_is_a_medium_link():
    n = Net()
    a, b = n.domain("mpesa-a.com"), n.domain("mpesa-b.com")
    n.link("mpesa-a.com", "domain", "mpesa-b.com", "redirects_to", ["redirect"])
    assert n.clusters("mpesa-a.com") == []                                         # one medium link only
    n.link("mpesa-a.com", "ip_address", "8.8.8.8", "resolves_to")
    n.link("mpesa-b.com", "ip_address", "8.8.8.8", "resolves_to")
    assert len(n.clusters("mpesa-a.com")) == 1 and a != b


def test_commonness_decays_a_nodes_weight_and_generic_nodes_are_ignored():
    n = Net()
    for i in range(6):
        n.link(f"mpesa-{i}.com", "analytics_id", "google_analytics:g-shared", "uses_analytics_id")
    (c,) = n.clusters("mpesa-0.com")
    assert len(c.members) == 6                                                      # 6 users: weight 0.8*5/6 still strong
    wide = Net()
    for i in range(16):
        wide.link(f"mpesa-{i}.com", "analytics_id", "google_analytics:g-agency", "uses_analytics_id")
    assert wide.clusters("mpesa-0.com") == []                                       # 16 users: 0.8*5/16 = 0.25, below medium
    generic = Net()
    for i in range(25):
        generic.link(f"mpesa-{i}.com", "whatsapp", "+254700000002", "uses_whatsapp")
    assert generic.clusters("mpesa-0.com") == []                                    # used everywhere: generic, ignored


def test_a_nodes_other_users_that_were_never_investigated_do_not_join():
    n = Net()
    n.link("mpesa-a.com", "whatsapp", "+254700000001", "uses_whatsapp")
    d = Entity("domain", "never-investigated.com", "never-investigated.com")      # in the graph, not a candidate
    node = Entity("whatsapp", "+254700000001", "+254700000001")
    ev = Evidence(n.iid, node.id, "x", "extracted_indicator", "+254700000001")
    n.h.graph.persist(n.iid, [d, node], [ev], [Relationship(n.iid, d.id, node.id, "uses_whatsapp", 0.9, ev.id)])
    assert n.clusters("mpesa-a.com") == []


def test_clusters_are_transitive_and_exclude_unrelated_domains():
    n = Net()
    n.link("mpesa-a.com", "whatsapp", "+254700000001", "uses_whatsapp")
    n.link("mpesa-b.com", "whatsapp", "+254700000001", "uses_whatsapp")
    n.link("mpesa-b.com", "telegram", "mpesa_help", "uses_telegram")
    n.link("mpesa-c.com", "telegram", "mpesa_help", "uses_telegram")
    n.link("mpesa-d.com", "registrar", "cheap registrar llc", "registered_with")
    (c,) = n.clusters("mpesa-a.com")
    assert sorted(c.names.values()) == ["mpesa-a.com", "mpesa-b.com", "mpesa-c.com"]


# -- persistence, evidence, merging ----------------------------------------------------------------------------------------

def test_a_campaign_is_created_with_cited_evidence_and_derived_relationships():
    n = Net()
    ev_a = n.link("mpesa-a.com", "whatsapp", "+254700000001", "uses_whatsapp")
    ev_b = n.link("mpesa-b.com", "whatsapp", "+254700000001", "uses_whatsapp")
    (res,) = n.run("mpesa-a.com")
    assert res["created"] and res["public_id"].startswith("WT-CMP-") and len(res["members"]) == 2
    (camp,) = n.campaigns()
    assert camp["status"] == "active" and camp["correlation_score"] >= 70
    rels = n.h.graph.conn.execute("SELECT * FROM relationships WHERE relationship_type IN ('shares_phone','member_of_campaign')").fetchall()
    assert {r["relationship_type"] for r in rels} == {"shares_phone", "member_of_campaign"}
    known = {r["id"] for r in n.h.graph.conn.execute("SELECT id FROM evidence")}
    assert all(r["evidence_id"] in known for r in rels)                              # nothing derived without a citation
    corr = json.loads(n.h.graph.conn.execute("SELECT observed_value FROM evidence WHERE evidence_type='correlation'").fetchone()[0])
    assert corr["link"] == "shares_phone" and set(corr["based_on"]) == {ev_a, ev_b} and corr["nodes"] == ["whatsapp:+254700000001"]
    assert all(n.h.store.get(i)["campaign_id"] == camp["id"] for i in n.ids.values())
    ev = n.h.store.campaign_events(camp["id"])
    assert [e["event"] for e in ev] == ["created"] and ev[0]["detail"]["members"] == ["mpesa-a.com", "mpesa-b.com"]


def test_persisting_twice_changes_nothing_and_a_new_member_expands_the_campaign():
    n = Net()
    for d in ("mpesa-a.com", "mpesa-b.com"):
        n.link(d, "whatsapp", "+254700000001", "uses_whatsapp")
    n.run("mpesa-a.com")
    n.run("mpesa-a.com")
    (camp,) = n.campaigns()
    assert len(n.h.store.campaign_events(camp["id"])) == 1                           # idempotent: no phantom "expanded"
    n.link("mpesa-c.com", "whatsapp", "+254700000001", "uses_whatsapp")
    (res,) = n.run("mpesa-c.com")
    assert not res["created"] and res["new_members"] == 1 and len(n.campaigns()) == 1
    last = n.h.store.campaign_events(camp["id"])[0]
    assert last["event"] == "expanded" and last["detail"]["added"] == ["mpesa-c.com"] and last["detail"]["members"] == 3


def test_a_bridging_domain_merges_two_campaigns_into_the_oldest():
    n = Net()
    for d in ("mpesa-a.com", "mpesa-b.com"):
        n.link(d, "whatsapp", "+254700000001", "uses_whatsapp")
    n.run("mpesa-a.com")
    for d in ("mpesa-x.com", "mpesa-y.com"):
        n.link(d, "telegram", "mpesa_help", "uses_telegram")
    n.run("mpesa-x.com")
    first, second = n.campaigns()
    n.link("mpesa-b.com", "telegram", "mpesa_help", "uses_telegram")                 # b is now in both worlds
    (res,) = n.run("mpesa-b.com")
    assert res["merged_from"] == [second["public_id"]] and len(res["members"]) == 4
    cams = {c["public_id"]: c["status"] for c in n.campaigns()}
    assert cams == {first["public_id"]: "active", second["public_id"]: "merged"}
    members = n.h.graph.conn.execute("SELECT entity_id FROM campaign_entities WHERE campaign_id=?", (first["id"],)).fetchall()
    assert len(members) == 4 and n.h.graph.conn.execute("SELECT COUNT(*) FROM campaign_entities WHERE campaign_id=?", (second["id"],)).fetchone()[0] == 0
    assert n.h.store.campaign_events(first["id"])[0]["event"] == "merged"
    assert {n.h.store.get(i)["campaign_id"] for i in n.ids.values()} == {first["id"]}


def test_rebuild_reproduces_what_incremental_updates_found():
    n = Net()
    for d in ("mpesa-a.com", "mpesa-b.com", "mpesa-c.com"):
        n.link(d, "whatsapp", "+254700000001", "uses_whatsapp")
    n.link("mpesa-solo.com", "whatsapp", "+254700000099", "uses_whatsapp")
    out = n.cor.rebuild("M-PESA", n.iid)
    assert len(out) == 1 and len(out[0]["members"]) == 3 and len(n.campaigns()) == 1
    assert n.h.store.get(n.ids["mpesa-solo.com"])["campaign_id"] is None


def test_confidence_rises_with_independent_strong_evidence():
    one, two = Net(), Net()
    for d in ("mpesa-a.com", "mpesa-b.com"):
        one.link(d, "whatsapp", "+254700000001", "uses_whatsapp")
        two.link(d, "whatsapp", "+254700000001", "uses_whatsapp")
        two.link(d, "payment_identifier", "paybill:123456", "uses_payment_identifier")
    assert two.clusters("mpesa-a.com")[0].confidence > one.clusters("mpesa-a.com")[0].confidence


# -- effect on scoring ---------------------------------------------------------------------------------------------------------------

def per_domain_rdap(request):
    """Registry stub whose nameservers differ per domain, as real ones do (the shared stub gives everyone the same pair)."""
    import httpx
    from test_hunter_enrich import BOOTSTRAP
    if request.url.host == "data.iana.org":
        return httpx.Response(200, json=BOOTSTRAP)
    name = request.url.path.rsplit("/", 1)[-1].replace(".", "-")
    rec = {"events": [{"eventAction": "registration", "eventDate": "2026-09-28T00:00:00Z"}],
           "nameservers": [{"ldhName": f"ns1.{name}-dns.example"}]}
    return httpx.Response(200, json=rec)


def phishing_net(path=":memory:"):
    """Two real pipeline runs: the same phishing kit on two domains, so they share WhatsApp, analytics id and form endpoint."""
    h = Harness({("mpesa-first.com", "A"): ["8.8.8.8"], ("mpesa-second.com", "A"): ["8.8.4.4"]}, per_domain_rdap, path=path)
    h.ctx.en.acquire = FakeAcquire(lambda d: SiteCapture(d, [fx("phishing_login.html", d)]))
    ids = []
    for d in ("mpesa-first.com", "mpesa-second.com"):
        cid = h.add(d)
        h.batch()
        if h.store.get(cid)["status"] != "QUEUED":
            h.store.requeue(cid, stage="light")
        h.batch()
        ids.append(cid)
    return h, ids


def test_the_pipeline_forms_a_campaign_and_linked_domains_cite_it_in_their_scores():
    h, (a, b) = phishing_net()
    (camp,) = [dict(r) for r in h.graph.conn.execute("SELECT * FROM campaigns")]
    assert h.store.get(a)["campaign_id"] == h.store.get(b)["campaign_id"] == camp["id"]
    assert "campaign WT-CMP-" in h.store.history(b)[-2]["detail"] or "campaign WT-CMP-" in " ".join(x["detail"] or "" for x in h.store.history(b))
    for cid in (a, b):
        row = h.store.latest_score(cid)
        linked = [r for r in row["reasons"] if r["signal"] == "linked_suspicious_infrastructure"]
        assert linked and linked[0]["weight"] == 10 and linked[0]["evidence_ids"] and camp["public_id"] in linked[0]["evidence"]
        known = {r["id"] for r in h.graph.conn.execute("SELECT id FROM evidence")}
        assert set(linked[0]["evidence_ids"]) <= known
        assert sum(r["weight"] for r in row["reasons"]) == pytest.approx(row["score"])
    assert any(x["trigger"] == "campaign_change" for x in h.store.score_history(a))     # the first domain was rescored when the second arrived


def test_linked_domains_cannot_lift_each_other_in_a_loop():
    h, (a, b) = phishing_net()
    before = (h.store.latest_score(a)["score"], h.store.latest_score(b)["score"])
    for _ in range(3):
        rescore(h.store, h.graph, h.cfg, h.ctx.brands, a, "t")
        rescore(h.store, h.graph, h.cfg, h.ctx.brands, b, "t")
    after = (h.store.latest_score(a)["score"], h.store.latest_score(b)["score"])
    assert before == after
    signals = {r["signal"]: r["weight"] for r in h.store.latest_score(a)["reasons"]}
    assert signals["linked_suspicious_infrastructure"] == 10                          # once, not compounding


def test_a_weak_neighbour_does_not_count_as_suspicious_infrastructure():
    n = Net()
    for d in ("mpesa-a.com", "mpesa-b.com"):
        n.link(d, "whatsapp", "+254700000001", "uses_whatsapp")
    n.run("mpesa-a.com")
    a, b = n.ids["mpesa-a.com"], n.ids["mpesa-b.com"]
    n.h.store.record_score(a, trigger="t", score=20, classification="LOW", assessment="complete", version="1", config_hash="x",
                           content_hash="h1", reasons=[], coverage={})
    res, _ = rescore(n.h.store, n.h.graph, n.h.cfg, n.h.ctx.brands, b, "t")
    assert "linked_suspicious_infrastructure" not in {r.signal for r in res.reasons}


def test_a_rescore_that_crosses_the_line_escalates_a_settled_candidate():
    h, (a, b) = phishing_net()
    h.store.conn.execute("UPDATE hunt_candidates SET status='SCORED' WHERE id=?", (b,))
    h.store.conn.execute("DELETE FROM hunt_scores WHERE candidate_id=?", (b,))
    h.cfg.scoring.high_min = 76
    rescore_and_route(h.store, h.graph, h.cfg, h.ctx.brands, b, "campaign_change")
    assert h.store.get(b)["status"] == "ESCALATED"


# -- the analyst's questions -------------------------------------------------------------------------------------------------------------

def test_graph_queries_answer_the_briefs_questions():
    h, (a, b) = phishing_net()
    q = GraphQueries(h.store, h.graph)
    users = q.domains_using("whatsapp", "+254700000001")
    assert [u["domain"] for u in users] == ["mpesa-first.com", "mpesa-second.com"] and all(u["evidence_id"] for u in users)
    assert users[0]["classification"] in {"HIGH_PRIORITY", "SUSPICIOUS"} and users[0]["market"]
    assert [d["domain"] for d in q.domains_using("phone_number", "+254700000001")] == [u["domain"] for u in users]   # same identity
    (camp,) = q.campaigns_for_indicator("whatsapp", "+254700000001")
    assert camp["members_using"] == 2 and q.campaigns_for_indicator("whatsapp", "+000") == []
    assert q.domains_using("ip_address", "8.8.8.8")[0]["domain"] == "mpesa-first.com"
    fd = q.first_discovered(a)
    assert fd["source"] == "certificate_transparency" and fd["depth"] == 0
    wa = next(r for r in h.store.list(limit=100) if r["indicator_type"] == "whatsapp")
    chain = q.what_led_to(wa["id"])
    assert [c["canonical"] for c in chain][-1] == "+254700000001" and chain[-1]["via"]["where"] == "link"


def test_campaign_view_has_counts_theme_reasons_events_and_a_graph():
    h, (a, b) = phishing_net()
    q = GraphQueries(h.store, h.graph)
    (c,) = q.campaigns()
    assert c["name"].startswith("M-PESA Credential phishing Cluster #") and c["theme"] == "Credential phishing"
    assert c["infrastructure"]["Domains"] == 3 and c["infrastructure"]["WhatsApp"] == 1 and c["infrastructure"]["IPs"] == 2
    # the credential collector both sites post to is part of the operation (a strong form-endpoint link)
    assert {m["domain"] for m in c["members"]} == {"mpesa-first.com", "mpesa-second.com", "collector.example"}
    links = {w["link"] for w in c["why_related"]}
    assert {"shares_whatsapp" if False else "shares_phone", "shares_analytics_id", "shares_form_endpoint"} <= links
    assert all(w["based_on"] for w in c["why_related"]) and c["events"][-1]["event"] == "created"
    g = q.subgraph(c["public_id"])
    types = {n["type"] for n in g["nodes"]}
    assert {"domain", "whatsapp", "ip_address", "analytics_id"} <= types
    assert all(e["evidence_id"] for e in g["edges"]) and {n["id"] for n in g["nodes"]} >= {e["target"] for e in g["edges"]}
    assert sum(1 for n in g["nodes"] if n["member"]) == 3
    assert q.campaign("WT-CMP-9999-0001") is None and q.subgraph("nope") == {"nodes": [], "edges": []}


def test_indicators_and_entity_views_are_grouped_for_the_investigation_page():
    h, (a, b) = phishing_net()
    q = GraphQueries(h.store, h.graph)
    groups = q.indicators_of(a)
    assert {"WhatsApp", "IPs", "Nameservers", "Domains", "Analytics IDs"} <= set(groups) and "Campaign" not in groups
    view = q.entity_view(a)
    assert view["candidate"]["canonical"] == "mpesa-first.com" and view["scores"] and view["lineage"][0]["canonical"] == "mpesa-first.com"
    assert any(r["relationship_type"] == "member_of_campaign" for r in view["outgoing"])
    assert q.entity_view("domain:nope") is None


def test_correlation_config_validation():
    base = {"brands": [{"name": "B", "aliases": ["bee"]}]}
    for bad in ({"strong_weight": 0.2}, {"weak_weight": 0.5}, {"generic_node_max_domains": 1}, {"min_pair_confidence": 1.5}, {"bogus": 1}):
        with pytest.raises(ConfigError):
            parse({**base, "correlation": bad})
    c = parse({**base, "correlation": {"common_nameserver_markers": ["NS.Example"]}})
    assert c.correlation.common_nameserver_markers == ["ns.example"]
