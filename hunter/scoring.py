"""Deterministic, explainable risk scoring.

`score()` is a pure function of `ScoreInputs` and the config. `gather_inputs()` builds those
inputs from stored evidence only, so any score can be reproduced offline from the database:
a number nobody can regenerate is a number nobody can defend. There is no model in this
path, and nothing adjusts a weight automatically; weights change only by editing config, and
every stored score records the config hash it was computed under.

Every reason carries a weight and where it came from: evidence ids from the graph store, or an
explicit non-evidence basis (`domain_name`, `config`). The weights of all reasons, including the
cap and clamp adjustments, sum to the score exactly.

Absence is not zero. If the page could not be seen (blocked, challenged, JavaScript-only, not
fetched) or the name does not resolve, a low score is reported as UNASSESSED rather than LOW,
unless the domain is official or trusted by configuration. Missing RDAP data is never a risk
factor.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

from core.trusted_domains import is_trusted_domain

from .config import Brand, HuntConfig, ScoringConfig
from .prescore import is_official, is_shared_hosting, prescore

SCORING_VERSION = "1"
CLASSES = ("LOW", "WATCH", "SUSPICIOUS", "HIGH_PRIORITY")

FAMILY = {
    "infrastructure": {"brand_in_domain", "brand_typo", "related_brand_in_domain", "recently_registered",
                       "new_certificate", "known_malicious_infrastructure", "linked_suspicious_infrastructure"},
    "credential": {"login_form", "pin_field", "otp_field", "card_field", "id_number_field",
                   "cross_origin_credential_form"},
    "channel": {"whatsapp_cta", "telegram_cta"},
    "payment": {"payment_instruction", "fee_language", "guaranteed_returns", "crypto_wallet",
                "external_payment_domain"},
    "language": {"credential_language", "urgency_language", "reward_language"},
}
_FAMILY_OF = {sig: fam for fam, sigs in FAMILY.items() for sig in sigs}
_STRONG_NODES = {"phone_number", "whatsapp", "telegram", "payment_identifier", "crypto_wallet", "analytics_id"}
_PHONE_TYPES = ("phone_number", "whatsapp")
_PAYISH = re.compile(r"\b(?:pay|payment|checkout|deposit|buy|donate|wallet)\b", re.I)


@dataclass
class Ev:
    id: str
    type: str
    url: str | None
    at: str
    facts: dict


@dataclass
class BadReuse:
    node_type: str
    node_value: str
    neighbor: str
    verdict: str
    evidence_ids: list


@dataclass
class Linked:
    campaign: str
    neighbor: str
    intrinsic: float
    evidence_ids: list


@dataclass
class ScoreInputs:
    domain: str
    brand: Brand
    now: datetime
    dns: Ev | None = None
    rdap: Ev | None = None
    tls: Ev | None = None
    pages: list = field(default_factory=list)      # latest page_signals per URL
    http: list = field(default_factory=list)       # latest http_response per URL
    bad_reuse: list = field(default_factory=list)
    threat_hits: list = field(default_factory=list)
    linked: list = field(default_factory=list)


@dataclass
class Reason:
    signal: str
    weight: float
    evidence: str
    basis: str = "evidence"                        # evidence | domain_name | config | analyst | adjustment
    evidence_ids: list = field(default_factory=list)
    family: str | None = None

    def dict(self) -> dict:
        return {"signal": self.signal, "weight": self.weight, "evidence": self.evidence, "basis": self.basis,
                "evidence_ids": list(self.evidence_ids), "family": self.family}


@dataclass
class RiskScore:
    score: int
    classification: str
    assessment: str                                # complete | partial | insufficient
    reasons: list
    coverage: dict
    unassessed: list
    version: str = SCORING_VERSION
    config_hash: str = ""

    def content_hash(self) -> str:
        blob = {"v": self.version, "cfg": self.config_hash, "score": self.score, "class": self.classification,
                "assessment": self.assessment, "coverage": self.coverage,
                "reasons": [[r.signal, r.weight, sorted(r.evidence_ids)] for r in self.reasons]}
        return hashlib.sha256(json.dumps(blob, sort_keys=True).encode()).hexdigest()

    def dict(self) -> dict:
        return {"score": self.score, "classification": self.classification, "assessment": self.assessment,
                "reasons": [r.dict() for r in self.reasons], "coverage": self.coverage,
                "unassessed": self.unassessed, "scoring_version": self.version, "config_hash": self.config_hash}


def config_hash(cfg: HuntConfig, brand: Brand) -> str:
    sc = cfg.scoring
    blob = {"scoring": {k: getattr(sc, k) for k in sorted(sc.__dataclass_fields__)},
            "prescore": {"w": cfg.prescore.weights, "k": cfg.prescore.keywords},
            "brand": {"aliases": brand.aliases, "related": brand.related_brands, "official": brand.official_domains,
                      "excluded": brand.excluded_brands}}
    return hashlib.sha256(json.dumps(blob, sort_keys=True, default=str).encode()).hexdigest()[:16]


def band(score: float, sc: ScoringConfig) -> str:
    if score >= sc.high_min:
        return "HIGH_PRIORITY"
    if score >= sc.suspicious_min:
        return "SUSPICIOUS"
    if score >= sc.watch_min:
        return "WATCH"
    return "LOW"


def _age_days(iso: str | None, now: datetime) -> float | None:
    if not iso:
        return None
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return None
    dt = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    return max((now - dt).total_seconds() / 86400, 0.0)


def _is_trusted(domain: str, sc: ScoringConfig) -> str | None:
    """Reason a domain is trusted by classification, or None. Never for shared-hosting subdomains:
    a trust discount on `x.<platform>` would let an attacker earn it by signing up."""
    if is_shared_hosting(domain):
        return None
    d = domain.lower()
    if any(d == t or d.endswith("." + t) for t in sc.trusted_domains):
        return "administrator-trusted domain"
    if any(d.endswith(s if s.startswith(".") else "." + s) for s in sc.trusted_suffixes):
        return "administrator-trusted suffix"
    return "listed trusted domain" if is_trusted_domain(d) else None


# ------------------------------------------------------------------------------------------------
def score(inp: ScoreInputs, cfg: HuntConfig, chash: str = "") -> RiskScore:
    sc, w = cfg.scoring, cfg.scoring.weights
    reasons: list[Reason] = []
    official = is_official(inp.domain, inp.brand)

    def add(signal, evidence, ids=(), basis="evidence", weight=None):
        wt = w[signal] if weight is None and signal in w else (weight or 0.0)
        reasons.append(Reason(signal, wt, evidence, basis, list(dict.fromkeys(ids))[:6], _FAMILY_OF.get(signal)))

    # -- coverage -----------------------------------------------------------------------------
    dns_status = inp.dns.facts.get("status") if inp.dns else "missing"
    rdap_status = inp.rdap.facts.get("status") if inp.rdap else "missing"
    tls_status = inp.tls.facts.get("status") if inp.tls else "missing"
    assessed = [p for p in inp.pages if not p.facts.get("unassessed_reason")]
    page_reasons = sorted({p.facts["unassessed_reason"] for p in inp.pages if p.facts.get("unassessed_reason")}
                          | {h.facts.get("error_kind") or f"HTTP {h.facts.get('status')}" for h in inp.http
                             if not any(p.url == h.url for p in inp.pages) and (h.facts.get("error_kind") or h.facts.get("status", 200) >= 400)})
    page_cov = "assessed" if assessed else ("unassessed" if (inp.pages or inp.http) else "not_fetched")
    coverage = {"dns": dns_status, "rdap": rdap_status, "tls": tls_status, "page": page_cov}

    # -- domain-name signals (basis: the name itself) --------------------------------------------------
    name_ps = prescore(inp.domain, inp.brand, cfg.prescore)
    brand_in_name = False
    for r in name_ps.reasons:
        if r["signal"] == "brand_token":
            add("brand_in_domain", r["evidence"], basis="domain_name")
            brand_in_name = True
        elif r["signal"] == "brand_typo":
            add("brand_typo", r["evidence"], basis="domain_name")
            brand_in_name = True
        elif r["signal"] == "related_brand_token":
            add("related_brand_in_domain", r["evidence"], basis="domain_name")
            brand_in_name = True

    # -- registration and certificate ------------------------------------------------------------------------
    rd = inp.rdap.facts if inp.rdap else {}
    age = _age_days(rd.get("registered_at"), inp.now) if rd.get("status") == "registered" else None
    if age is not None and inp.rdap is not None and age <= sc.recently_registered_days:
        add("recently_registered", f"registered {age:.0f} day(s) ago ({rd.get('registrar') or 'registrar unknown'})", [inp.rdap.id])
    tls = inp.tls
    cert_age = _age_days(tls.facts.get("not_before"), inp.now) if tls is not None and tls.facts.get("status") == "ok" else None
    if tls is not None and cert_age is not None and cert_age <= sc.new_certificate_days:
        add("new_certificate", f"certificate issued {cert_age:.0f} day(s) ago by {tls.facts.get('issuer')}", [tls.id])

    # -- page signals (only pages whose content was actually seen) -----------------------------------------------
    def pages_with(pred):
        return [p for p in assessed if pred(p.facts)]

    def ids(ps):
        return [p.id for p in ps]

    def forms_of(f):
        return f.get("forms") or []

    login = pages_with(lambda f: any(fm.get("high_sensitivity") for fm in forms_of(f)))
    if login:
        kinds = sorted({k for p in login for fm in forms_of(p.facts) for k in fm.get("high_sensitivity", [])})
        add("login_form", f"form requests: {', '.join(kinds)} ({login[0].url})", ids(login))
    flag_rules = (
        ("pin_field", "solicits_pin", "form asks for a PIN"), ("otp_field", "solicits_otp", "form asks for an OTP / verification code"),
        ("card_field", "solicits_card", "form asks for card number or CVV"), ("id_number_field", "solicits_id", "form asks for an ID/passport number"),
        ("cross_origin_credential_form", "cross_origin_form", "form submits to a different site"),
        ("whatsapp_cta", "whatsapp_cta", "page directs visitors to WhatsApp"), ("telegram_cta", "telegram_cta", "page directs visitors to Telegram"),
        ("payment_instruction", "payment_instruction", "page gives payment instructions (Paybill/Till/send-to)"),
        ("fee_language", "fee_language", "page asks for an activation/registration/withdrawal fee"),
        ("guaranteed_returns", "guaranteed_returns", "page promises guaranteed returns / doubling money"),
        ("crypto_wallet", "crypto_wallet", "page lists a crypto wallet address"),
        ("credential_language", "credential_language", "page text asks for account verification / PIN / OTP"),
        ("urgency_language", "urgency_language", "page uses account-suspension / urgency language"),
        ("reward_language", "reward_language", "page uses prize / approved-loan language"),
    )
    for signal, flag, text in flag_rules:
        hit = pages_with(lambda f, flag=flag: f.get("flags", {}).get(flag))
        if hit:
            detail = text
            if signal == "cross_origin_credential_form":
                hosts = sorted({fm["action_host"] for p in hit for fm in forms_of(p.facts) if fm.get("cross_origin") and fm.get("action_host")})
                detail = f"form submits to {', '.join(hosts) or 'another site'}"
            add(signal, f"{detail} ({hit[0].url})", ids(hit))
    pay_links = [(p, e) for p in assessed for e in p.facts.get("external_links", [])
                 if e.get("category") == "external" and _PAYISH.search(e.get("label") or "")]
    if pay_links:
        add("external_payment_domain", f"payment-style link to unrelated site {pay_links[0][1]['host']}", ids([p for p, _ in pay_links]))
    brand_mentioned = pages_with(lambda f: f.get("flags", {}).get("brand_mentioned"))
    if brand_mentioned and not official:
        add("brand_off_official_domain", f"brand named on page ({', '.join(brand_mentioned[0].facts['brand']['terms'])}) "
            f"but the domain is not an official one", ids(brand_mentioned))

    # -- known-bad infrastructure ------------------------------------------------------------------------------------
    if inp.bad_reuse or inp.threat_hits:
        parts = [f"{b.node_type} {b.node_value} also used by {b.neighbor} ({b.verdict})" for b in inp.bad_reuse[:2]]
        parts += [f"threat feed: {t.facts.get('feed', 'unknown')}" for t in inp.threat_hits[:1]]
        add("known_malicious_infrastructure", "; ".join(parts),
            [i for b in inp.bad_reuse for i in b.evidence_ids] + [t.id for t in inp.threat_hits])

    if inp.linked:
        names = ", ".join(f"{l.neighbor} ({l.intrinsic:.0f})" for l in inp.linked[:3])
        add("linked_suspicious_infrastructure", f"campaign {inp.linked[0].campaign}: {len(inp.linked)} linked domain(s) score "
            f"suspicious on their own: {names}", [i for l in inp.linked for i in l.evidence_ids])

    # -- discounts ----------------------------------------------------------------------------------------------------
    serious = {"pin_field", "otp_field", "card_field", "cross_origin_credential_form", "payment_instruction",
               "fee_language", "guaranteed_returns", "known_malicious_infrastructure"}
    fired = {r.signal for r in reasons}
    trust = _is_trusted(inp.domain, sc)
    authority = False
    if official:
        add("official_domain", f"{inp.domain} is on or under a configured official domain", basis="config")
        authority = True
    elif trust:
        add("trusted_third_party", f"{inp.domain}: {trust}", basis="config")
        authority = True
    if (age is not None and inp.rdap is not None and age >= sc.established_years * 365 and assessed
            and not (fired & serious) and not official):
        add("established_organization", f"registered {age / 365:.1f} years ago and the page shows no serious signals",
            [inp.rdap.id] + ids(assessed[:2]))
    if any(p.facts.get("flags", {}).get("advisory_context") for p in assessed) \
            and not any(p.facts.get("flags", {}).get("credential_form") for p in assessed):
        adv = pages_with(lambda f: f.get("flags", {}).get("advisory_context"))
        add("advisory_context", "page discusses scams and asks for no credentials", ids(adv))

    # -- combination --------------------------------------------------------------------------------------------------------
    families = {r.family for r in reasons if r.weight > 0 and r.family}
    if len(families) >= sc.multi_signal_min_families:
        add("multiple_signals", f"signals in {len(families)} independent families: {', '.join(sorted(families))}",
            [i for r in reasons if r.weight > 0 for i in r.evidence_ids][:6])

    total = sum(r.weight for r in reasons)
    brand_relevant = brand_in_name or bool(brand_mentioned)
    if not brand_relevant and total > sc.unbranded_cap:
        reasons.append(Reason("no_brand_relevance_cap", sc.unbranded_cap - total,
                              f"nothing ties this domain to {inp.brand.name}; capped at {sc.unbranded_cap}", "adjustment"))
        total = sc.unbranded_cap
    final = int(round(min(max(total, 0), 100)))
    if final != round(total):
        reasons.append(Reason("score_clamp", final - round(total), "score limited to the 0-100 range", "adjustment"))
        total = final
    # keep the invariant exact despite rounding of fractional weights
    drift = final - sum(r.weight for r in reasons)
    if abs(drift) > 1e-9:
        reasons.append(Reason("rounding", drift, "rounding of fractional weights", "adjustment"))

    unassessed = []
    if not authority:
        if dns_status == "missing":
            unassessed.append("no DNS evidence")
        elif dns_status == "nxdomain":
            unassessed.append("name does not resolve")
        elif dns_status == "error":
            unassessed.append("DNS lookup failed")
        elif page_cov == "not_fetched":
            unassessed.append("page not fetched")
        elif page_cov == "unassessed":
            unassessed.append("page content not assessable: " + (", ".join(page_reasons) or "unknown"))
    cls = band(final, sc)
    if cls == "LOW" and unassessed:
        cls = "UNASSESSED"
    assessment = "insufficient" if dns_status == "missing" else ("partial" if unassessed else "complete")
    return RiskScore(final, cls, assessment, reasons, coverage, unassessed, SCORING_VERSION, chash)


# ------------------------------------------------------------------------------------------------
def _facts(row) -> dict:
    try:
        v = json.loads(row["observed_value"])
        return v if isinstance(v, dict) else {}
    except (ValueError, TypeError):
        return {}


def gather_inputs(graph, cid: str, domain: str, brand: Brand, cfg: HuntConfig, now: datetime, store=None) -> ScoreInputs:
    """Rebuild score inputs from stored evidence only (no network, no clock except `now`)."""
    conn = graph.conn
    rows = conn.execute("SELECT * FROM evidence WHERE entity_id=? ORDER BY observed_at, rowid", (cid,)).fetchall()
    latest: dict[tuple, Ev] = {}
    for r in rows:
        key = (r["evidence_type"], r["source_url"] if r["evidence_type"] in {"page_signals", "http_response"} else "")
        latest[key] = Ev(r["id"], r["evidence_type"], r["source_url"], r["observed_at"], _facts(r))
    inp = ScoreInputs(domain, brand, now)
    inp.dns, inp.rdap, inp.tls = (latest.get((t, "")) for t in ("dns_lookup", "rdap_lookup", "tls_lookup"))
    inp.pages = [e for (t, _), e in sorted(latest.items(), key=lambda kv: str(kv[0])) if t == "page_signals"]
    inp.http = [e for (t, _), e in sorted(latest.items(), key=lambda kv: str(kv[0])) if t == "http_response"]
    inp.threat_hits = [e for (t, _), e in latest.items() if t == "threat_feed_hit"]

    confirmed = set(cfg.scoring.confirmed_verdicts)
    seen = set()
    for r in conn.execute("""SELECT r.target_entity_id AS node, r.evidence_id AS ev, e.entity_type AS t, e.canonical_value AS v
                             FROM relationships r JOIN entities e ON e.id=r.target_entity_id
                             WHERE r.source_entity_id=? AND e.entity_type IN (%s)""" % ",".join("?" * len(_STRONG_NODES)),
                          (cid, *sorted(_STRONG_NODES))).fetchall():
        # A number is one identity whether it was found as a phone or as a WhatsApp contact.
        types = _PHONE_TYPES if r["t"] in _PHONE_TYPES else (r["t"],)
        nodes = [n["id"] for n in conn.execute(
            "SELECT id FROM entities WHERE canonical_value=? AND entity_type IN (%s)" % ",".join("?" * len(types)),
            (r["v"], *types))]
        neighbors: dict = {}
        for n in nodes:
            for nb in conn.execute("SELECT source_entity_id AS s, evidence_id AS ev FROM relationships WHERE target_entity_id=? AND source_entity_id!=?", (n, cid)):
                neighbors.setdefault(nb["s"], []).append(nb["ev"])
        if len(neighbors) > cfg.scoring.shared_node_max_domains:
            continue                                                     # used everywhere: generic, not a link
        for nb, evs in neighbors.items():
            v = conn.execute("SELECT verdict FROM analyst_verdicts WHERE entity_id=? ORDER BY id DESC LIMIT 1", (nb,)).fetchone()
            name = conn.execute("SELECT canonical_value FROM entities WHERE id=?", (nb,)).fetchone()
            if v and v["verdict"].lower() in confirmed and (r["t"], r["v"], nb) not in seen:
                seen.add((r["t"], r["v"], nb))
                inp.bad_reuse.append(BadReuse(r["t"], r["v"], name["canonical_value"] if name else nb, v["verdict"],
                                              [r["ev"], *evs[:1]]))
    if store is not None:
        member_ev = conn.execute("SELECT evidence_id FROM relationships WHERE source_entity_id=? AND relationship_type='member_of_campaign' "
                                 "ORDER BY rowid DESC LIMIT 1", (cid,)).fetchone()
        for r in conn.execute("""SELECT c.public_id AS pub, ce2.entity_id AS nb FROM campaign_entities ce1
                                 JOIN campaign_entities ce2 ON ce2.campaign_id=ce1.campaign_id
                                 JOIN campaigns c ON c.id=ce1.campaign_id
                                 WHERE ce1.entity_id=? AND ce2.entity_id!=? AND c.status!='merged'""", (cid, cid)).fetchall():
            other = store.latest_score(r["nb"])
            if not other or not member_ev:
                continue
            # The neighbour's own evidence only: its score minus whatever this same factor added to it,
            # so two linked domains cannot lift each other in a loop.
            own = other["score"] - sum(x["weight"] for x in other["reasons"] if x["signal"] == "linked_suspicious_infrastructure")
            if own >= cfg.scoring.suspicious_min:
                name = conn.execute("SELECT canonical_value FROM entities WHERE id=?", (r["nb"],)).fetchone()
                inp.linked.append(Linked(r["pub"], name["canonical_value"] if name else r["nb"], own, [member_ev["evidence_id"]]))
    return inp


def rescore(store, graph, cfg: HuntConfig, brands: dict, cid: str, trigger: str, now: datetime | None = None):
    """Recompute from stored evidence and append to history if anything material changed.

    Returns (RiskScore, record_result). Safe to call any time; no network.
    """
    cand = store.get(cid)
    if cand is None:
        raise KeyError(cid)
    from .dispositions import effective_cfg          # administrator-approved trust joins the configured trust
    cfg = effective_cfg(store, cfg)
    brand = brands.get(cand["brand"]) or next(iter(brands.values()))
    now = now or store.clock()
    inp = gather_inputs(graph, cid, cand["canonical"], brand, cfg, now, store)
    result = score(inp, cfg, config_hash(cfg, brand))
    rec = store.record_score(cid, trigger=trigger, score=result.score, classification=result.classification,
                             assessment=result.assessment, version=result.version, config_hash=result.config_hash,
                             content_hash=result.content_hash(), reasons=[r.dict() for r in result.reasons],
                             coverage={**result.coverage, "unassessed": result.unassessed})
    return result, rec


def target_status(result: RiskScore, sc: ScoringConfig) -> str:
    """Queue status after scoring: ESCALATED surfaces the candidate to an analyst."""
    high = result.classification == "HIGH_PRIORITY"
    if high or (sc.escalate_at == "SUSPICIOUS" and result.classification == "SUSPICIOUS"):
        return "ESCALATED"
    return "SCORED"


def rescore_and_route(store, graph, cfg, brands, cid: str, trigger: str, now=None):
    """Rescore, and if that pushes a settled candidate over the escalation line, escalate it."""
    result, rec = rescore(store, graph, cfg, brands, cid, trigger, now)
    if rec["recorded"] and target_status(result, cfg.scoring) == "ESCALATED":
        store.escalate(cid, f"{trigger}: score {result.score} {result.classification}")
    return result, rec
