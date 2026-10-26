"""Hunter configuration: brands, pre-score weights, budgets.

Unknown keys raise ConfigError. A misspelt weight that silently kept its default
would change scoring without anyone noticing, and a hunt with no brands would
"succeed" by finding nothing, which is the failure this codebase exists to prevent.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


class ConfigError(ValueError):
    pass


DEFAULT_WEIGHTS: dict[str, float] = {
    "brand_token": 30,
    "related_brand_token": 18,
    "brand_typo": 25,
    "brand_exact_label": 12,  # the whole label is the brand, e.g. mpesa.com on a non-official domain
    "credential_keyword": 15,
    "money_keyword": 15,
    "support_keyword": 8,
    "market_keyword": 5,
    "unusual_tld": 8,
    "free_hosting": 8,
    "new_certificate": 10,
    "new_registration": 10,
    "combination": 10,      # brand signal together with a credential or money keyword
    "unbranded_cap": 20,    # ceiling when no brand signal exists: keywords alone are noise
}

DEFAULT_KEYWORDS: dict[str, list[str]] = {
    "credential": [
        "login", "signin", "secure", "security", "verify", "verification", "account", "update",
        "portal", "kyc", "pin", "otp", "activate", "activation", "unlock", "confirm", "auth",
        "access", "reset",
    ],
    "money": [
        "loan", "loans", "credit", "invest", "investment", "investing", "reward", "rewards",
        "promo", "promotion", "offer", "bonus", "giveaway", "win", "withdraw", "withdrawal",
        "wallet", "cash", "earn", "profit", "forex", "crypto", "double", "pay", "payment",
    ],
    "support": [
        "support", "help", "helpdesk", "care", "customer", "service", "contact", "agent", "hotline",
    ],
}

# Abbreviations are matched as whole hyphen-separated parts only.
MARKET_TOKENS: dict[str, list[str]] = {
    "kenya": ["kenya", "ke"], "tanzania": ["tanzania", "tz"], "mozambique": ["mozambique", "mz"],
    "drc": ["drc", "congo"], "lesotho": ["lesotho", "ls"], "ethiopia": ["ethiopia", "et"],
    "ghana": ["ghana", "gh"], "egypt": ["egypt", "eg"], "south africa": ["southafrica", "za"],
}

UNUSUAL_TLDS = frozenset({
    "xyz", "top", "click", "online", "site", "icu", "shop", "live", "vip", "buzz", "cyou", "cfd",
    "sbs", "work", "rest", "gq", "tk", "ml", "ga", "cf", "monster", "life", "world", "today",
    "support", "help", "loan", "loans", "win", "bid", "cam", "mom", "fun",
})

FREE_HOSTING = (
    "vercel.app", "netlify.app", "lovable.app", "firebaseapp.com", "web.app", "github.io",
    "pages.dev", "000webhostapp.com", "weebly.com", "wixsite.com", "blogspot.com",
    "workers.dev", "onrender.com", "glitch.me", "herokuapp.com",
)

# Two-part public suffixes relevant to the markets in scope. No PSL dependency.
TWO_PART_SUFFIXES = frozenset({
    "co.ke", "or.ke", "go.ke", "ne.ke", "ac.ke", "co.tz", "or.tz", "go.tz", "co.za", "org.za",
    "co.ls", "co.mz", "com.et", "com.gh", "com.eg", "com.ng", "co.uk", "com.au", "co.ug", "co.zm",
})


@dataclass
class Brand:
    name: str
    aliases: list[str]
    related_brands: list[str] = field(default_factory=list)
    official_domains: list[str] = field(default_factory=list)
    excluded_brands: list[str] = field(default_factory=list)
    markets: list[str] = field(default_factory=list)

    def __post_init__(self):
        self.official_domains = [d.strip().lower().rstrip(".") for d in self.official_domains]


@dataclass
class PreScoreConfig:
    weights: dict[str, float] = field(default_factory=lambda: dict(DEFAULT_WEIGHTS))
    keywords: dict[str, list[str]] = field(default_factory=lambda: {k: list(v) for k, v in DEFAULT_KEYWORDS.items()})
    store_max: int = 30
    light_max: int = 55
    full_max: int = 75


@dataclass
class PermutationConfig:
    enabled: bool = True
    max_candidates: int = 400
    max_labels: int = 3000
    max_tlds_per_label: int = 6
    tlds: list[str] = field(default_factory=lambda: ["com", "co.ke", "net", "org", "online", "xyz"])


@dataclass
class CTConfig:
    enabled: bool = True
    min_interval_seconds: float = 2.0
    max_rows_per_term: int = 300
    max_names_per_certificate: int = 50
    timeout_seconds: float = 30.0


@dataclass
class EnrichConfig:
    dns_timeout_seconds: float = 5.0
    rdap_min_interval_seconds: float = 1.0
    rdap_timeout_seconds: float = 15.0
    rdap_cache_hours: float = 24.0
    tls_timeout_seconds: float = 7.0
    concurrency: int = 5
    max_deep_per_hour: int = 30
    # Days until each successive re-check of a name that does not resolve yet.
    # Once the schedule is spent the candidate is IGNORED (visibly, and re-queueable).
    unregistered_recheck_days: list[float] = field(default_factory=lambda: [1, 3, 7, 14, 30])
    max_batch_seconds: float = 600.0     # time budget: candidates not started by then are deferred, visibly


@dataclass
class AcquisitionConfig:
    # The landing page of a candidate is a targeted inspection (like opening a link) and
    # does not obey robots.txt by default; its verdict is still recorded. Everything past
    # it is crawling and always obeys robots.txt. Set true to obey it everywhere.
    obey_robots_landing: bool = False
    max_pages_per_domain: int = 3
    max_bytes: int = 1_500_000
    timeout_seconds: float = 10.0
    total_timeout_seconds: float = 25.0   # wall clock per page; a trickling server cannot hold a worker
    page_delay_seconds: float = 1.0       # politeness gap between pages of one site
    snapshot_chars: int = 20000
    robots_max_bytes: int = 200_000


@dataclass
class SignalsConfig:
    default_region: str = "KE"           # market context for local phone numbers
    # Extra *literal* phrases per rule (extends a built-in rule or defines a new one).
    # Literals only, never regex: an operator-supplied pattern must not be able to hang a worker.
    phrases: dict[str, list[str]] = field(default_factory=dict)
    disable: list[str] = field(default_factory=list)          # built-in rule names to turn off
    infrastructure_domains: list[str] = field(default_factory=list)   # extra "not a lead" link targets
    max_snippets: int = 3
    snippet_chars: int = 160
    text_cap: int = 100_000


# Initial weights, per the brief; treat as a starting point, not as truth. Entries marked (+)
# were added beyond the brief's list because the signals exist and would otherwise be unscored.
DEFAULT_RISK_WEIGHTS: dict[str, float] = {
    "brand_in_domain": 15, "brand_typo": 15, "related_brand_in_domain": 8,
    "recently_registered": 10, "new_certificate": 5,
    "login_form": 10, "pin_field": 20, "otp_field": 20,
    "card_field": 20, "id_number_field": 8, "cross_origin_credential_form": 12,        # (+)
    "whatsapp_cta": 8, "telegram_cta": 8,
    "payment_instruction": 12, "fee_language": 12, "guaranteed_returns": 12, "crypto_wallet": 8,
    "external_payment_domain": 10,
    "credential_language": 8, "urgency_language": 6, "reward_language": 5,             # (+)
    "brand_off_official_domain": 8,                                                     # (+) brief: "one risk feature"
    "multiple_signals": 10, "known_malicious_infrastructure": 25,
    "linked_suspicious_infrastructure": 10,                                             # (+) in the brief's UI example
    "official_domain": -50, "trusted_third_party": -30, "established_organization": -25,
    "advisory_context": -15,                                                            # (+)
}
NEGATIVE_WEIGHTS = {"official_domain", "trusted_third_party", "established_organization", "advisory_context"}


@dataclass
class ScoringConfig:
    weights: dict[str, float] = field(default_factory=lambda: dict(DEFAULT_RISK_WEIGHTS))
    watch_min: int = 31
    suspicious_min: int = 56
    high_min: int = 76
    recently_registered_days: float = 30.0
    new_certificate_days: float = 7.0
    established_years: float = 5.0
    unbranded_cap: int = 40                  # ceiling when nothing ties the page to the brand
    multi_signal_min_families: int = 3
    shared_node_max_domains: int = 20        # a node used by more domains than this is generic, not a link
    confirmed_verdicts: list[str] = field(default_factory=lambda: [
        "confirmed_malicious", "confirmed_scam", "confirmed_impersonation"])
    trusted_domains: list[str] = field(default_factory=list)      # admin-maintained
    trusted_suffixes: list[str] = field(default_factory=list)     # e.g. .go.ke, .ac.ke
    escalate_at: str = "HIGH_PRIORITY"
    insight_min_support: int = 3             # cases needed before a pattern or false-positive class is surfaced


@dataclass
class PivotConfig:
    max_depth: int = 3                  # Domain A depth 0 -> phone depth 1 -> Domain B depth 2 -> handle depth 3
    max_pivots_per_entity: int = 10     # children one candidate may spawn
    max_jobs_per_lineage: int = 50      # per campaign once one exists, otherwise per originating candidate
    max_pivots_per_day: int = 200
    max_search_queries_per_day: int = 100
    search_min_interval_seconds: float = 2.0
    search_timeout_seconds: float = 30.0
    queue_medium: bool = True           # email, social profile, iframe/payment-style links
    queue_low: bool = False             # generic outbound links: stored for the graph, not investigated
    deep_if_ancestor_score: int = 56    # a candidate reached from a suspicious one earns a deep pass
    reverse_ip: bool = False            # optional external reverse-IP lookup (free, rate limited)
    shared_ip_max_domains: int = 50     # more than this on one IP = shared hosting, not a link
    search: bool = True                 # external public search for indicator pivots


@dataclass
class CorrelationConfig:
    strong_weight: float = 0.8
    medium_weight: float = 0.35
    weak_weight: float = 0.05            # recorded as supporting detail; can never create a campaign alone
    uncommon_max_domains: int = 5        # beyond this many users a node's weight decays as max/users
    generic_node_max_domains: int = 20   # beyond this a node is treated as generic and ignored
    min_pair_confidence: float = 0.5
    medium_links_needed: int = 2         # independent medium links that stand in for one strong link
    max_cluster_size: int = 300
    # Mass-market DNS/registrar infrastructure: sharing it says "same provider", not "same actor".
    common_nameserver_markers: list[str] = field(default_factory=lambda: [
        "ns.cloudflare.com", "awsdns-", "domaincontrol.com", "registrar-servers.com", "googledomains.com",
        "azure-dns", "dnsmadeeasy.com", "nsone.net", "wixdns.net", "squarespacedns.com", "hostinger", "dns-parking.com"])
    campaign_alert_growth: int = 3       # members added at once that count as "expanded materially"


@dataclass
class SchedulerConfig:
    ct_minutes: float = 30.0
    permutation_hours: float = 24.0
    search_discovery_hours: float = 6.0
    enrich_seconds: float = 60.0
    enrich_limit: int = 20
    refresh_minutes: float = 60.0
    alerts_seconds: float = 60.0
    purge_hours: float = 24.0
    tick_seconds: float = 5.0
    job_timeout_seconds: float = 900.0
    breaker_failures: int = 5            # consecutive failures that open a provider's circuit
    breaker_cooldown_minutes: float = 30.0
    refresh_batch: int = 50
    benign_refresh_days: float = 30.0   # candidates an analyst marked benign / false positive are re-checked this rarely
    # Days until a settled candidate is looked at again, by classification. Re-checks are how a parked
    # domain that turns into a login page gets noticed.
    refresh_days: dict = field(default_factory=lambda: {"HIGH_PRIORITY": 1.0, "SUSPICIOUS": 2.0, "WATCH": 7.0,
                                                       "LOW": 30.0, "UNASSESSED": 7.0})


@dataclass
class AlertsConfig:
    enabled: bool = True
    cooldown_hours: float = 24.0         # the same alert key is not raised again inside this window
    risk_delta: int = 25                 # a rescore this much higher counts as a major increase
    provider_failures: int = 3           # consecutive failures of an important provider
    webhook_env: str = "WATCHTOWER_ALERT_WEBHOOK"   # URL read from this environment variable; unset = no outbound alerts


@dataclass
class RetentionConfig:
    personal_data_days: float = 90.0
    keep_campaign_indicators: bool = True    # indicators tied to a campaign are kept while the campaign is active
    rejection_days: float = 30.0


@dataclass
class SearchDiscoveryConfig:
    enabled: bool = True
    max_queries_per_run: int = 6
    max_results_per_query: int = 10
    templates: list[str] = field(default_factory=lambda: [
        '"{brand}" "verify account"', '"{brand}" "account activation"', '"{brand}" "WhatsApp"', '"{brand}" "Telegram"',
        '"{brand}" "investment"', '"{brand}" "loan approval"', '"{brand}" "withdraw"', '"{brand}" "registration fee"',
        '"{brand}" (site:vercel.app OR site:netlify.app OR site:pages.dev)',
        '"{brand}" (site:web.app OR site:firebaseapp.com OR site:github.io)'])


@dataclass
class HuntConfig:
    brands: list[Brand]
    prescore: PreScoreConfig = field(default_factory=PreScoreConfig)
    permutations: PermutationConfig = field(default_factory=PermutationConfig)
    ct: CTConfig = field(default_factory=CTConfig)
    max_candidates_per_run: int = 500
    enrichment: EnrichConfig = field(default_factory=EnrichConfig)
    acquisition: AcquisitionConfig = field(default_factory=AcquisitionConfig)
    signals: SignalsConfig = field(default_factory=SignalsConfig)
    scoring: ScoringConfig = field(default_factory=ScoringConfig)
    pivots: PivotConfig = field(default_factory=PivotConfig)
    correlation: CorrelationConfig = field(default_factory=CorrelationConfig)
    scheduler: SchedulerConfig = field(default_factory=SchedulerConfig)
    alerts: AlertsConfig = field(default_factory=AlertsConfig)
    retention: RetentionConfig = field(default_factory=RetentionConfig)
    search_discovery: SearchDiscoveryConfig = field(default_factory=SearchDiscoveryConfig)

    def brand(self, name: str | None = None) -> Brand:
        if name is None and len(self.brands) == 1:
            return self.brands[0]
        for b in self.brands:
            if b.name.lower() == (name or "").lower():
                return b
        raise ConfigError(f"unknown brand: {name!r} (configured: {[b.name for b in self.brands]})")


def _only(section: str, data: dict, allowed: set[str]) -> dict:
    if not isinstance(data, dict):
        raise ConfigError(f"{section} must be a mapping")
    extra = set(data) - allowed
    if extra:
        raise ConfigError(f"unknown key(s) in {section}: {sorted(extra)}")
    return data


def parse(raw: dict[str, Any]) -> HuntConfig:
    raw = _only("hunter config", raw or {}, {"brands", "prescore", "permutations",
                                             "certificate_transparency", "budgets", "enrichment",
                                             "acquisition", "signals", "scoring", "pivots", "correlation", "scheduler", "alerts", "retention",
                                             "search_discovery"})
    if not raw.get("brands"):
        raise ConfigError("no brands configured: a hunt with nothing to look for would report a clean result")
    brands = []
    for item in raw["brands"]:
        item = _only("brand", item, {"name", "aliases", "related_brands", "official_domains",
                                     "excluded_brands", "markets"})
        if not item.get("name") or not item.get("aliases"):
            raise ConfigError("every brand needs a name and at least one alias")
        brands.append(Brand(**item))

    pre = PreScoreConfig()
    p = _only("prescore", raw.get("prescore") or {}, {"bands", "weights", "keywords"})
    for key, value in _only("prescore.weights", p.get("weights") or {}, set(DEFAULT_WEIGHTS)).items():
        pre.weights[key] = float(value)
    for key, value in _only("prescore.keywords", p.get("keywords") or {}, set(DEFAULT_KEYWORDS)).items():
        pre.keywords[key] = [str(x).lower() for x in value]
    bands = _only("prescore.bands", p.get("bands") or {}, {"store_max", "light_max", "full_max"})
    pre.store_max = int(bands.get("store_max", pre.store_max))
    pre.light_max = int(bands.get("light_max", pre.light_max))
    pre.full_max = int(bands.get("full_max", pre.full_max))
    if not 0 <= pre.store_max < pre.light_max < pre.full_max < 100:
        raise ConfigError("prescore.bands must satisfy 0 <= store_max < light_max < full_max < 100")

    perm = PermutationConfig()
    for key, value in _only("permutations", raw.get("permutations") or {},
                            {"enabled", "max_candidates", "max_labels", "max_tlds_per_label", "tlds"}).items():
        setattr(perm, key, list(value) if key == "tlds" else bool(value) if key == "enabled" else int(value))
    ct = CTConfig()
    for key, value in _only("certificate_transparency", raw.get("certificate_transparency") or {},
                            set(CTConfig.__dataclass_fields__)).items():
        setattr(ct, key, type(getattr(ct, key))(value))
    budgets = _only("budgets", raw.get("budgets") or {}, {"max_candidates_per_run"})
    enrich = EnrichConfig()
    for key, value in _only("enrichment", raw.get("enrichment") or {}, set(EnrichConfig.__dataclass_fields__)).items():
        setattr(enrich, key, [float(x) for x in value] if key == "unregistered_recheck_days"
                else type(getattr(enrich, key))(value))
    if enrich.concurrency < 1 or not enrich.unregistered_recheck_days:
        raise ConfigError("enrichment.concurrency must be >= 1 and unregistered_recheck_days non-empty")
    acq = AcquisitionConfig()
    for key, value in _only("acquisition", raw.get("acquisition") or {},
                            set(AcquisitionConfig.__dataclass_fields__)).items():
        setattr(acq, key, type(getattr(acq, key))(value))
    if acq.max_pages_per_domain < 1 or acq.max_bytes < 1024:
        raise ConfigError("acquisition.max_pages_per_domain must be >= 1 and max_bytes >= 1024")
    sig = SignalsConfig()
    for key, value in _only("signals", raw.get("signals") or {}, set(SignalsConfig.__dataclass_fields__)).items():
        if key == "phrases":
            if not isinstance(value, dict) or not all(isinstance(v, list) and all(isinstance(x, str) and x.strip() and len(x) <= 200
                                                                                  for x in v) for v in value.values()):
                raise ConfigError("signals.phrases must map rule names to lists of literal phrases (max 200 chars)")
            sig.phrases = {str(k): [x.strip() for x in v] for k, v in value.items()}
        elif key in {"disable", "infrastructure_domains"}:
            setattr(sig, key, [str(x).lower() for x in value])
        else:
            setattr(sig, key, type(getattr(sig, key))(value))
    sc = ScoringConfig()
    raw_sc = _only("scoring", raw.get("scoring") or {}, set(ScoringConfig.__dataclass_fields__) - {"weights"} | {"weights", "bands"})
    for key, value in _only("scoring.weights", raw_sc.get("weights") or {}, set(DEFAULT_RISK_WEIGHTS)).items():
        value = float(value)
        # A sign slip (a discount that adds risk, or a risk factor that subtracts it) would be silent.
        if (key in NEGATIVE_WEIGHTS and value > 0) or (key not in NEGATIVE_WEIGHTS and value < 0):
            raise ConfigError(f"scoring.weights.{key} must be {'<= 0' if key in NEGATIVE_WEIGHTS else '>= 0'}")
        sc.weights[key] = value
    for key, value in _only("scoring.bands", raw_sc.get("bands") or {}, {"watch_min", "suspicious_min", "high_min"}).items():
        setattr(sc, key, int(value))
    for key, value in raw_sc.items():
        if key in {"weights", "bands"}:
            continue
        if key in {"confirmed_verdicts", "trusted_domains", "trusted_suffixes"}:
            setattr(sc, key, [str(x).lower() for x in value])
        else:
            setattr(sc, key, type(getattr(sc, key))(value))
    if not 0 < sc.watch_min < sc.suspicious_min < sc.high_min <= 100:
        raise ConfigError("scoring.bands must satisfy 0 < watch_min < suspicious_min < high_min <= 100")
    if sc.escalate_at not in {"SUSPICIOUS", "HIGH_PRIORITY"}:
        raise ConfigError("scoring.escalate_at must be SUSPICIOUS or HIGH_PRIORITY")
    pv = PivotConfig()
    for key, value in _only("pivots", raw.get("pivots") or {}, set(PivotConfig.__dataclass_fields__)).items():
        setattr(pv, key, type(getattr(pv, key))(value))
    if pv.max_depth < 0 or pv.max_pivots_per_entity < 0 or pv.max_jobs_per_lineage < 1:
        raise ConfigError("pivots: max_depth/max_pivots_per_entity must be >= 0 and max_jobs_per_lineage >= 1")
    co = CorrelationConfig()
    for key, value in _only("correlation", raw.get("correlation") or {}, set(CorrelationConfig.__dataclass_fields__)).items():
        setattr(co, key, [str(x).lower() for x in value] if key == "common_nameserver_markers" else type(getattr(co, key))(value))
    if not 0 < co.weak_weight < co.medium_weight < co.strong_weight < 1:
        raise ConfigError("correlation weights must satisfy 0 < weak < medium < strong < 1")
    if co.generic_node_max_domains < 2 or not 0 < co.min_pair_confidence < 1:
        raise ConfigError("correlation.generic_node_max_domains must be >= 2 and min_pair_confidence in (0, 1)")
    def section(name, obj):
        for key, value in _only(name, raw.get(name) or {}, set(type(obj).__dataclass_fields__)).items():
            cur = getattr(obj, key)
            if isinstance(cur, dict):
                value = {str(k).upper(): float(v) for k, v in value.items()}
            elif isinstance(cur, list):
                value = [str(x) for x in value]
            else:
                value = type(cur)(value)
            setattr(obj, key, value)
        return obj
    sch, al, ret = section("scheduler", SchedulerConfig()), section("alerts", AlertsConfig()), section("retention", RetentionConfig())
    sd = section("search_discovery", SearchDiscoveryConfig())
    if sch.breaker_failures < 1 or sch.tick_seconds <= 0 or min(sch.refresh_days.values(), default=1) <= 0:
        raise ConfigError("scheduler: breaker_failures >= 1, tick_seconds > 0 and refresh_days > 0 are required")
    if ret.personal_data_days <= 0 or al.cooldown_hours < 0:
        raise ConfigError("retention.personal_data_days must be > 0 and alerts.cooldown_hours >= 0")
    if any("{brand}" not in t for t in sd.templates):
        raise ConfigError("every search_discovery template must contain {brand}")
    return HuntConfig(brands, pre, perm, ct, int(budgets.get("max_candidates_per_run", 500)), enrich, acq, sig, sc, pv, co,
                      sch, al, ret, sd)


def load(path: str | Path = "hunter.yaml") -> HuntConfig:
    p = Path(path)
    if not p.exists():
        raise ConfigError(f"hunter config not found: {p}")
    try:
        return parse(yaml.safe_load(p.read_text()) or {})
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {p}: {exc}") from exc
