"""Analyst dispositions and what they are allowed to change.

A disposition is a human judgement recorded with who made it, when, and why; it is append-only and
nothing is deleted. Its effects are deterministic and narrow:

  CONFIRMED_SCAM / CONFIRMED_IMPERSONATION
      mirrored into the graph's analyst verdicts, so other domains sharing a strong node with it gain
      `known_malicious_infrastructure`; every campaign member and node-sharing domain is rescored.
  FALSE_POSITIVE / BENIGN
      kept (never deleted); re-checked rarely (`benign_refresh_days`); no more score-based alerts for it,
      though new evidence (a change) still can raise one.
  SUSPICIOUS / MONITOR / UNREVIEWED
      recorded; no scoring effect.

What dispositions never do: change a scoring weight. Patterns seen in confirmed cases and classes of
repeated false positives are *surfaced* (`insights`) for an administrator, and a trusted classification
only takes effect when an administrator approves it (`approve_trusted`), after which it is logged and the
affected domains are rescored under the new, attributed config hash. Small samples are never acted on:
nothing is surfaced below `scoring.insight_min_support` cases.
"""
from __future__ import annotations

import itertools
from collections import Counter, defaultdict
from dataclasses import replace
from typing import Any
from datetime import datetime, timezone

from .graphq import GraphQueries
from .normalize import InvalidIndicator, normalize
from .prescore import registrable, split_domain
from .scoring import rescore_and_route
from .store import CLEARED_DISPOSITIONS, CONFIRMED_DISPOSITIONS

VERDICT_FOR = {"UNREVIEWED": "unreviewed", "BENIGN": "benign", "FALSE_POSITIVE": "false_positive", "SUSPICIOUS": "suspicious",
               "CONFIRMED_IMPERSONATION": "confirmed_impersonation", "CONFIRMED_SCAM": "confirmed_scam", "MONITOR": "monitor"}
KEY_SIGNALS = {"brand_in_domain", "brand_typo", "recently_registered", "login_form", "pin_field", "otp_field", "card_field",
               "cross_origin_credential_form", "whatsapp_cta", "telegram_cta", "payment_instruction", "fee_language",
               "guaranteed_returns", "crypto_wallet", "credential_language", "urgency_language", "reward_language",
               "external_payment_domain", "known_malicious_infrastructure"}


def effective_cfg(store, cfg):
    """The configured scoring settings plus administrator-approved trusted domains."""
    extra = [e["value"] for e in store.admin_trusted()]
    if not extra:
        return cfg
    return replace(cfg, scoring=replace(cfg.scoring, trusted_domains=[*cfg.scoring.trusted_domains, *extra]))


def apply_disposition(store, graph, cfg, brands, *, disposition: str, analyst: str, identity_source: str, reason: str = "",
                      notes: str = "", candidate_id: str | None = None, campaign_id: str | None = None) -> dict:
    row = store.add_disposition(disposition=disposition, analyst=analyst, identity_source=identity_source, reason=reason,
                                notes=notes, candidate_id=candidate_id, campaign_id=campaign_id)
    comment = f"{reason}".strip()[:1800] + (f" | {notes}".strip()[:150] if notes else "")
    entity = candidate_id
    if campaign_id:
        entity = None
    verdict = VERDICT_FOR[disposition]
    if candidate_id:
        graph.verdict(candidate_id, verdict, comment, f"{analyst} ({identity_source})")
    else:
        # campaign-level verdicts reuse the graph's table; the entity column is unused for them
        graph.conn.execute("INSERT INTO analyst_verdicts(entity_id,campaign_id,verdict,analyst_comment,analyst_identifier,created_at,previous_verdict) "
                           "VALUES(?,?,?,?,?,?,?)", ("", campaign_id, verdict, comment, f"{analyst} ({identity_source})",
                                                     datetime.now(timezone.utc).isoformat(), row["previous"]))
        graph.conn.commit()
    affected: list[str] = []
    if disposition in CONFIRMED_DISPOSITIONS:
        affected = _neighbours(store, graph, candidate_id, campaign_id)
        cfg = effective_cfg(store, cfg)
        for cid in affected:
            rescore_and_route(store, graph, cfg, brands, cid, "analyst_verdict")
    return {**row, "entity": entity, "campaign_id": campaign_id, "rescored": len(affected)}


def _neighbours(store, graph, candidate_id, campaign_id) -> list[str]:
    """Domains whose scores can change because of a confirmation: campaign mates and node-sharing domains."""
    q = GraphQueries(store, graph)
    seeds = [candidate_id] if candidate_id else [r["entity_id"] for r in graph.conn.execute(
        "SELECT entity_id FROM campaign_entities WHERE campaign_id=?", (campaign_id,))]
    out: dict[str, None] = {}
    for seed in seeds:
        if seed is None:
            continue
        for ce in graph.conn.execute("""SELECT ce2.entity_id FROM campaign_entities ce1
                                        JOIN campaign_entities ce2 ON ce2.campaign_id=ce1.campaign_id
                                        WHERE ce1.entity_id=? AND ce2.entity_id!=?""", (seed, seed)):
            out[ce["entity_id"]] = None
        for group in q.indicators_of(seed).values():
            for ind in group:
                for d in q.domains_using(ind["type"], ind["value"]):
                    if d["id"] != seed:
                        out[d["id"]] = None
    return [c for c in out if store.get(c) and store.latest_score(c)]


def _signals(store, cid: str) -> set[str]:
    row = store.latest_score(cid)
    return {r["signal"] for r in (row["reasons"] if row else []) if r["weight"] > 0} & KEY_SIGNALS


def _combos(signals: set[str]) -> list[tuple]:
    s = sorted(signals)[:8]
    return [c for n in (2, 3) for c in itertools.combinations(s, n)]


def insights(store, graph, cfg) -> dict:
    """Surfaced for an administrator; applied to nothing."""
    need = cfg.scoring.insight_min_support
    with store._lock:
        rows = store.conn.execute("SELECT id, canonical, disposition FROM hunt_candidates WHERE indicator_type='domain' AND disposition IS NOT NULL").fetchall()
    confirmed = [r for r in rows if r["disposition"] in CONFIRMED_DISPOSITIONS]
    cleared = [r for r in rows if r["disposition"] in CLEARED_DISPOSITIONS]
    pos: Counter = Counter()
    neg: Counter = Counter()
    for r in confirmed:
        pos.update(_combos(_signals(store, r["id"])))
    for r in cleared:
        neg.update(_combos(_signals(store, r["id"])))
    patterns: list[dict[str, Any]] = [{"signals": list(c), "confirmed_cases": n, "false_positive_cases": neg.get(c, 0),
                 "note": "observed in confirmed cases; scoring weights are unchanged"}
                for c, n in pos.most_common(40) if n >= need]
    patterns.sort(key=lambda p: (-p["confirmed_cases"], p["false_positive_cases"], -len(p["signals"])))
    trusted = {t.lower() for t in cfg.scoring.trusted_domains} | {e["value"] for e in store.admin_trusted()}
    by_domain, by_suffix = defaultdict(list), defaultdict(list)
    for r in cleared:
        reg = registrable(r["canonical"])
        by_domain[reg].append(r["canonical"])
        labels, suffix = split_domain(r["canonical"])
        if "." in suffix or suffix in {"gov", "edu", "org"}:
            by_suffix["." + suffix].append(r["canonical"])
    suggestions = [{"type": "trusted_domain", "value": d, "cases": len(v), "examples": sorted(set(v))[:5],
                    "needs": "administrator approval"} for d, v in sorted(by_domain.items()) if len(v) >= need and d not in trusted]
    suggestions += [{"type": "trusted_suffix", "value": s, "cases": len(v), "examples": sorted(set(v))[:5],
                     "needs": "administrator approval (edit scoring.trusted_suffixes in hunter.yaml)"}
                    for s, v in sorted(by_suffix.items()) if len(v) >= need and s not in {x.lower() for x in cfg.scoring.trusted_suffixes}]
    return {"min_support": need, "confirmed": len(confirmed), "cleared": len(cleared), "patterns": patterns[:20], "suggestions": suggestions}


def _clean_domain(value: str) -> str:
    """Accept a domain or a pasted URL; the trust applies to the registrable domain."""
    try:
        return registrable(normalize(value, hint="domain").canonical)
    except InvalidIndicator as exc:
        raise ValueError(f"not a valid domain: {exc}")


def approve_trusted(store, graph, cfg, brands, domain: str, *, by: str, identity_source: str, reason: str) -> dict:
    domain = _clean_domain(domain)
    if not reason.strip():
        raise ValueError("a reason is required")
    items = store.admin_trusted()
    if any(e["value"] == domain for e in items):
        return {"domain": domain, "added": False, "rescored": 0}
    items.append({"value": domain, "by": by[:100], "identity_source": identity_source, "reason": reason.strip()[:500],
                  "at": datetime.now(timezone.utc).isoformat()})
    store.set_admin_trusted(items)
    n = 0
    for cand in store.list(limit=1_000_000):
        if cand["indicator_type"] == "domain" and registrable(cand["canonical"]) == domain and store.latest_score(cand["id"]):
            rescore_and_route(store, graph, effective_cfg(store, cfg), brands, cand["id"], "config_change")
            n += 1
    return {"domain": domain, "added": True, "rescored": n}


def remove_trusted(store, graph, cfg, brands, domain: str) -> dict:
    domain = _clean_domain(domain)
    items = store.admin_trusted()
    kept = [e for e in items if e["value"] != domain]
    if len(kept) == len(items):
        return {"domain": domain, "removed": False, "rescored": 0}
    store.set_admin_trusted(kept)
    n = 0
    for cand in store.list(limit=1_000_000):
        if cand["indicator_type"] == "domain" and registrable(cand["canonical"]) == domain and store.latest_score(cand["id"]):
            rescore_and_route(store, graph, effective_cfg(store, cfg), brands, cand["id"], "config_change")
            n += 1
    return {"domain": domain, "removed": True, "rescored": n}
