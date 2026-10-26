import pytest

from hunter.config import ConfigError, DEFAULT_WEIGHTS, load, parse
from hunter.permute import generate, generate_labels
from hunter.normalize import normalize
from hunter.prescore import band_for, is_official, levenshtein, prescore, skeleton


@pytest.fixture(scope="module")
def cfg():
    return load("hunter.yaml")


@pytest.fixture(scope="module")
def brand(cfg):
    return cfg.brand()


def ps(cfg, brand, domain, **kw):
    return prescore(domain, brand, cfg.prescore, **kw)


def signals(result):
    return {r["signal"] for r in result.reasons}


def test_official_domain_and_subdomains_score_zero(cfg, brand):
    for d in ["safaricom.co.ke", "login.safaricom.co.ke", "www.m-pesa.co.ke"]:
        r = ps(cfg, brand, d)
        assert r.score == 0 and r.band == "STORE" and signals(r) == {"official_domain"}


def test_official_suffix_trick_is_not_official(cfg, brand):
    assert "official_domain" not in signals(ps(cfg, brand, "safaricom.co.ke.evil-mpesa.com"))
    assert "official_domain" not in signals(ps(cfg, brand, "notsafaricom.co.ke"))


def test_unrelated_and_news_domains_stay_at_zero(cfg, brand):
    for d in ["news.bbc.co.uk", "nation.africa", "safari.example.com", "weather-login.com"]:
        assert ps(cfg, brand, d).band == "STORE", d


def test_keywords_without_brand_are_capped(cfg, brand):
    r = ps(cfg, brand, "shop-login-verify-loan.top")
    assert r.score <= cfg.prescore.weights["unbranded_cap"] and not r.has_brand_signal


def test_brand_plus_credential_plus_tld_climbs(cfg, brand):
    plain_brand = ps(cfg, brand, "mpesa-thing.com")
    lure = ps(cfg, brand, "mpesa-verify.xyz")
    assert lure.score > plain_brand.score
    assert {"brand_token", "credential_keyword", "unusual_tld", "combination"} <= signals(lure)
    assert lure.band in {"FULL", "HIGH"}


def test_every_reason_carries_weight_and_evidence(cfg, brand):
    for r in ps(cfg, brand, "mpesa-loan-ke.online").reasons:
        assert r["signal"] and isinstance(r["weight"], (int, float)) and r["evidence"]


def test_score_equals_sum_of_reason_weights_when_branded(cfg, brand):
    r = ps(cfg, brand, "mpesa-loan-ke.online")
    assert r.score == min(100, sum(x["weight"] for x in r.reasons))


def test_typos_and_lookalikes(cfg, brand):
    for d in ["mpessa-login.com", "mpsa-login.com", "rnpesa.com", "mpes4.com", "mpeesa.net"]:
        assert "brand_typo" in signals(ps(cfg, brand, d)), d
    assert skeleton("rnpesa") == "mpesa" and skeleton("mpes4") == "mpesa"


def test_short_alias_needs_a_whole_part(cfg):
    b = cfg.brand()
    b2 = type(b)(**{**b.__dict__, "aliases": ["saf"]})
    assert "brand_token" not in signals(prescore("safari-login.com", b2, cfg.prescore))
    assert "brand_token" in signals(prescore("saf-login.com", b2, cfg.prescore))


def test_excluded_competing_brand_is_not_a_lead(cfg, brand):
    r = ps(cfg, brand, "equity-bank-loan.co.ke")
    assert r.score == 0 and signals(r) == {"excluded_brand"}
    # but naming M-PESA as well keeps it a lead
    assert ps(cfg, brand, "equity-bank-mpesa-loan.co.ke").score > 0


def test_related_brand_weighs_less_than_primary(cfg, brand):
    assert ps(cfg, brand, "safaricom-promo.xyz").score < ps(cfg, brand, "mpesa-promo.xyz").score


def test_exact_brand_label_on_other_tld_is_a_lead(cfg, brand):
    r = ps(cfg, brand, "mpesa.com")
    assert "brand_exact_label" in signals(r) and r.band == "LIGHT"


def test_certificate_and_registration_age(cfg, brand):
    base = ps(cfg, brand, "mpesa-verify.com").score
    assert ps(cfg, brand, "mpesa-verify.com", cert_age_days=1).score == base + 10
    assert ps(cfg, brand, "mpesa-verify.com", domain_age_days=3).score == base + 10
    assert ps(cfg, brand, "mpesa-verify.com", cert_age_days=90).score == base


def test_free_hosting_and_market(cfg, brand):
    r = ps(cfg, brand, "mpesa-kenya.vercel.app")
    assert {"free_hosting", "market_keyword"} <= signals(r)


def test_bands_are_configurable_and_boundaries_inclusive(cfg):
    p = cfg.prescore
    assert [band_for(x, p) for x in (0, 30, 31, 55, 56, 75, 76, 100)] == \
        ["STORE", "STORE", "LIGHT", "LIGHT", "FULL", "FULL", "HIGH", "HIGH"]


def test_levenshtein():
    assert levenshtein("mpesa", "mpesa") == 0 and levenshtein("mpesa", "mpeza") == 1
    assert levenshtein("mpesa", "xxxxxxxx", 2) > 2


# -- config ---------------------------------------------------------------------

def base_cfg(**extra):
    return {"brands": [{"name": "B", "aliases": ["bee"]}], **extra}


def test_weight_override_applies():
    c = parse(base_cfg(prescore={"weights": {"brand_token": 50}}))
    assert c.prescore.weights["brand_token"] == 50
    assert c.prescore.weights["brand_typo"] == DEFAULT_WEIGHTS["brand_typo"]


@pytest.mark.parametrize("raw", [
    {},                                                             # no brands: must not "succeed"
    {"brands": []},
    base_cfg(prescore={"weights": {"brnad_token": 5}}),             # typo in a weight name
    base_cfg(prescore={"bands": {"store_max": 60}}),                # bands out of order
    base_cfg(bogus=1),
    {"brands": [{"name": "B"}]},                                    # alias required
    {"brands": [{"name": "B", "aliases": ["b"], "colour": "x"}]},
    base_cfg(permutations={"max_candidate": 5}),
])
def test_bad_config_is_rejected(raw):
    with pytest.raises(ConfigError):
        parse(raw)


def test_missing_config_file_is_an_error(tmp_path):
    with pytest.raises(ConfigError):
        load(tmp_path / "nope.yaml")


# -- permutations -------------------------------------------------------------------

def test_generation_is_bounded_and_deterministic(cfg, brand):
    a, b = generate(brand, cfg), generate(brand, cfg)
    assert [p.domain for p in a] == [p.domain for p in b]
    assert 0 < len(a) <= cfg.permutations.max_candidates
    assert len({p.domain for p in a}) == len(a)
    assert len(generate(brand, cfg, limit=10)) == 10


def test_generation_never_returns_official_or_invalid_names(cfg, brand):
    for p in generate(brand, cfg):
        assert not is_official(p.domain, brand)
        assert normalize(p.domain).canonical == p.domain, p.domain
        assert all(len(part) <= 63 for part in p.domain.split("."))


def test_generation_covers_the_expected_patterns(cfg, brand):
    labels = generate_labels(brand, 3000)
    for expected in ["mpesa-login", "mpesa-secure", "m-pesa-verify", "mpesa-kenya", "mpesa-tz",
                     "mpesaloan", "mpesa-investment", "mpesa-registration", "asepm"]:
        assert expected in labels, expected
    kinds = set(labels.values())
    assert {"affix", "market", "omission", "duplication", "transposition", "homoglyph", "reversed"} <= kinds


def test_selected_candidates_mix_kinds_and_tlds(cfg, brand):
    got = generate(brand, cfg)
    assert len({p.kind for p in got}) >= 6
    assert {p.domain.split(".", 1)[1] for p in got} == set(cfg.permutations.tlds[: cfg.permutations.max_tlds_per_label])


def test_generator_scales_down_to_a_tiny_budget(cfg, brand):
    small = parse({"brands": [{"name": "B", "aliases": ["bee"]}], "permutations": {"max_candidates": 5}})
    assert len(generate(small.brand(), small)) <= 5
