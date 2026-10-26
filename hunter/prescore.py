"""Cheap pre-score: decides how much investigation a candidate deserves.

Works from the indicator string alone (plus optional certificate/registration
age), so it can rank thousands of candidates before any network call. It is a
priority signal, not a verdict: the explainable risk score comes after evidence.

Signals combine rather than add up on their own. A keyword-only domain with no
brand signal is capped at `unbranded_cap`; the brand is what makes the rest
matter, which is how "M-PESA on a news site" stays low and "unfamiliar domain +
brand + verify" does not.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .config import (
    FREE_HOSTING, MARKET_TOKENS, TWO_PART_SUFFIXES, UNUSUAL_TLDS, Brand, PreScoreConfig,
)

BANDS = ("STORE", "LIGHT", "FULL", "HIGH")

_LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s"})


def plain(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower())


def skeleton(s: str) -> str:
    """Plain form with look-alike characters folded (0->o, 1->l, rn->m, vv->w)."""
    return plain(s).translate(_LEET).replace("rn", "m").replace("vv", "w")


def levenshtein(a: str, b: str, limit: int = 2) -> int:
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def split_domain(domain: str) -> tuple[list[str], str]:
    """(name labels, public suffix) without a PSL: last label, or a known two-part suffix."""
    labels = domain.lower().rstrip(".").split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in TWO_PART_SUFFIXES:
        return labels[:-2], ".".join(labels[-2:])
    return labels[:-1], labels[-1]


def registrable(domain: str) -> str:
    """Name plus public suffix (no PSL): the part a registry holds a record for."""
    labels, suffix = split_domain(domain)
    return f"{labels[-1]}.{suffix}" if labels else domain.lower()


def is_shared_hosting(domain: str) -> bool:
    """True for subdomains of free-hosting platforms, whose registration is the platform's."""
    d = domain.lower().rstrip(".")
    return any(d.endswith("." + h) for h in FREE_HOSTING)


def is_official(domain: str, brand: Brand) -> bool:
    d = domain.lower().rstrip(".")
    return any(d == o or d.endswith("." + o) for o in brand.official_domains)


def _token_in(token: str, label: str) -> bool:
    """Whole hyphen part for short tokens; substring of the folded label otherwise.

    A three-letter alias as a substring makes 'safari.example' look like 'saf'.
    """
    t = plain(token)
    if not t:
        return False
    parts = [plain(p) for p in re.split(r"[-_]", label)]
    if len(t) <= 3:
        return t in parts
    return t in plain(label) or any(t == p for p in parts)


def _typo_of(token: str, label: str) -> str | None:
    t = plain(token)
    if len(t) < 5:
        return None
    lp, ls = plain(label), skeleton(label)
    if t in lp:
        return None
    if skeleton(t) in ls:
        return f"look-alike characters spell '{t}'"
    for text in (lp, ls):
        for size in (len(t) - 1, len(t), len(t) + 1):
            for i in range(0, max(len(text) - size + 1, 0)):
                if levenshtein(t, text[i:i + size], 1) <= 1 and text[i:i + size] != t:
                    return f"'{text[i:i + size]}' is one edit from '{t}'"
    return None


@dataclass
class PreScore:
    score: int
    band: str
    reasons: list[dict] = field(default_factory=list)

    @property
    def has_brand_signal(self) -> bool:
        return any(r["signal"] in {"brand_token", "related_brand_token", "brand_typo"} for r in self.reasons)

    def dict(self) -> dict:
        return {"score": self.score, "band": self.band, "reasons": self.reasons}


def band_for(score: float, cfg: PreScoreConfig) -> str:
    if score <= cfg.store_max:
        return "STORE"
    if score <= cfg.light_max:
        return "LIGHT"
    if score <= cfg.full_max:
        return "FULL"
    return "HIGH"


def _kw_hit(words: list[str], labels: list[str]) -> str | None:
    for word in words:
        for label in labels:
            if _token_in(word, label):
                return word
    return None


def prescore(domain: str, brand: Brand, cfg: PreScoreConfig, *,
             cert_age_days: float | None = None,
             domain_age_days: float | None = None) -> PreScore:
    domain = domain.lower().rstrip(".")
    w = cfg.weights
    if is_official(domain, brand):
        return PreScore(0, "STORE", [{"signal": "official_domain", "weight": 0,
                                       "evidence": f"{domain} is on or under a configured official domain"}])

    labels, suffix = split_domain(domain)
    reasons: list[dict] = []

    def add(signal: str, weight: float, evidence: str):
        reasons.append({"signal": signal, "weight": weight, "evidence": evidence})

    brand_hit = next((a for a in brand.aliases for lb in labels if _token_in(a, lb)), None)
    related_hit = next((a for a in brand.related_brands for lb in labels if _token_in(a, lb)), None)
    typo_hit = None
    if not brand_hit:
        for a in (*brand.aliases, *(_label_of(o) for o in brand.official_domains)):
            for lb in labels:
                why = _typo_of(a, lb)
                if why:
                    typo_hit = f"label '{lb}': {why}"
                    break
            if typo_hit:
                break

    if not (brand_hit or related_hit or typo_hit):
        excluded = next((x for x in brand.excluded_brands for lb in labels if _token_in(x, lb)), None)
        if excluded:
            return PreScore(0, "STORE", [{"signal": "excluded_brand", "weight": 0,
                                           "evidence": f"names competing brand '{excluded}', not {brand.name}"}])

    if brand_hit:
        add("brand_token", w["brand_token"], f"'{brand_hit}' appears in {'.'.join(labels)}")
        if any(plain(lb) == plain(a) for a in brand.aliases for lb in labels[-1:]):
            add("brand_exact_label", w["brand_exact_label"],
                f"the registered name is exactly '{labels[-1]}' on a non-official domain")
    elif typo_hit:
        add("brand_typo", w["brand_typo"], typo_hit)
    elif related_hit:
        add("related_brand_token", w["related_brand_token"], f"related brand '{related_hit}' appears in {'.'.join(labels)}")

    groups = {g: _kw_hit(cfg.keywords.get(g, []), labels) for g in ("credential", "money", "support")}
    for group, hit in groups.items():
        if hit:
            add(f"{group}_keyword", w[f"{group}_keyword"], f"keyword '{hit}' in domain")

    market_pool = [t for m in (brand.markets or list(MARKET_TOKENS)) for t in MARKET_TOKENS.get(m.lower(), [plain(m)])]
    market = _kw_hit(market_pool, labels)
    if market:
        add("market_keyword", w["market_keyword"], f"market token '{market}'")
    if suffix.split(".")[-1] in UNUSUAL_TLDS and suffix not in TWO_PART_SUFFIXES:
        add("unusual_tld", w["unusual_tld"], f".{suffix} is a commonly abused TLD")
    host = domain
    if any(host.endswith("." + h) for h in FREE_HOSTING):
        add("free_hosting", w["free_hosting"], "hosted on a free/subdomain platform")
    if cert_age_days is not None and cert_age_days <= 7:
        add("new_certificate", w["new_certificate"], f"certificate issued {cert_age_days:.0f} day(s) ago")
    if domain_age_days is not None and domain_age_days <= 30:
        add("new_registration", w["new_registration"], f"registered {domain_age_days:.0f} day(s) ago")

    branded = any(r["signal"] in {"brand_token", "brand_typo", "related_brand_token"} for r in reasons)
    if branded and (groups["credential"] or groups["money"]):
        add("combination", w["combination"], "brand signal together with a credential/money keyword")

    total = sum(r["weight"] for r in reasons)
    if not branded:
        total = min(total, w["unbranded_cap"])
    total = int(max(0, min(100, round(total))))
    return PreScore(total, band_for(total, cfg), reasons)


def _label_of(domain: str) -> str:
    labels, _ = split_domain(domain)
    return labels[-1] if labels else domain
