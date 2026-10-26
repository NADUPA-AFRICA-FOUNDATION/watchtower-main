"""Market detection from page evidence, with a confidence.

A country-code TLD is deliberately a weak input (1 point): a .ke domain says where it
was registered, not whom it targets, and it is never enough on its own. Evidence that
counts: phone country codes, currencies, country/city/operator names, local payment
methods and script/language. Ambiguous tokens (MT, R, LE) are left out on purpose.

Returns `Unknown` when the best market has fewer than MIN_POINTS, and
`Multi-market / Group` when two or more markets are each supported by real evidence.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Sequence

MIN_POINTS = 3

MARKETS: dict[str, dict] = {
    "Kenya": {"dial": "+254", "tld": ".ke",
              "currency": r"(?<![a-z])(?:kes|ksh|kshs)(?![a-z])|kenyan?\s+shillings?",
              "terms": r"\b(?:kenya|kenyan|nairobi|mombasa|kisumu|safaricom|huduma|kra)\b",
              "payment": r"\blipa\s+na\s+m-?pesa\b|\bbuy\s+goods\b|\bpay\s?bill\b|\btill\s+(?:no|number)\b"},
    "Tanzania": {"dial": "+255", "tld": ".tz",
                 "currency": r"(?<![a-z])(?:tzs|tsh|tshs)(?![a-z])|tanzanian?\s+shillings?",
                 "terms": r"\b(?:tanzania|tanzanian|dar\s+es\s+salaam|dodoma|arusha|vodacom\s+tanzania)\b",
                 "payment": r"\blipa\s+namba\b"},
    "Mozambique": {"dial": "+258", "tld": ".mz",
                   "currency": r"(?<![a-z])mzn(?![a-z])|meticais?",
                   "terms": r"\b(?:mo[cç]ambique|mozambique|maputo|vodacom\s+mo[cç]ambique)\b",
                   "payment": r"\bconta\s+m-?pesa\b"},
    "Democratic Republic of the Congo": {"dial": "+243", "tld": ".cd",
                                         "currency": r"(?<![a-z])cdf(?![a-z])|francs?\s+congolais",
                                         "terms": r"\b(?:rdc|r[eé]publique\s+d[eé]mocratique\s+du\s+congo|kinshasa|lubumbashi|congo)\b",
                                         "payment": r""},
    "Lesotho": {"dial": "+266", "tld": ".ls",
                "currency": r"(?<![a-z])lsl(?![a-z])|\bmaloti\b",
                "terms": r"\b(?:lesotho|maseru|vodacom\s+lesotho)\b", "payment": r""},
    "Ethiopia": {"dial": "+251", "tld": ".et",
                 "currency": r"(?<![a-z])etb(?![a-z])|\bbirr\b",
                 "terms": r"\b(?:ethiopia|ethiopian|addis\s+ababa|safaricom\s+ethiopia)\b", "payment": r"",
                 "script": r"[ሀ-፿]"},
    "Ghana": {"dial": "+233", "tld": ".gh",
              "currency": r"(?<![a-z])ghs(?![a-z])|gh₵|ghana\s+cedis?|₵",
              "terms": r"\b(?:ghana|ghanaian|accra|kumasi|vodafone\s+ghana)\b", "payment": r""},
    "Egypt": {"dial": "+20", "tld": ".eg",
              "currency": r"(?<![a-z])egp(?![a-z])|egyptian\s+pounds?|جنيه",
              "terms": r"\b(?:egypt|egyptian|cairo|alexandria|vodafone\s+egypt)\b|مصر", "payment": r"",
              "script": r"[؀-ۿ]"},
    "South Africa": {"dial": "+27", "tld": ".za",
                     "currency": r"(?<![a-z])zar(?![a-z])|south\s+african\s+rands?",
                     "terms": r"\b(?:south\s+africa|south\s+african|johannesburg|cape\s+town|durban|pretoria|vodacom\s+south\s+africa)\b",
                     "payment": r""},
}
# Kiswahili is shared by Kenya and Tanzania, so it supports both a little and neither much.
_SWAHILI = re.compile(r"\b(?:karibu|asante|akaunti|simu|tuma\s+pesa|huduma\s+kwa\s+wateja|mkopo|kuthibitisha)\b", re.I)
_GROUP = re.compile(r"\b(?:vodacom\s+group|safaricom\s+group|m-?pesa\s+africa|across\s+africa|multiple\s+countries)\b", re.I)


@dataclass
class MarketGuess:
    market: str
    confidence: float
    evidence: list = field(default_factory=list)
    scores: dict = field(default_factory=dict)

    def facts(self) -> dict:
        return {"market": self.market, "confidence": self.confidence,
                "scores": dict(sorted(self.scores.items())), "evidence": self.evidence}


def detect_market(text: str, numbers: Sequence[str] = (), domain: str = "") -> MarketGuess:
    text = unicodedata.normalize("NFKC", text or "")[:100_000]
    pts: dict[str, float] = {m: 0.0 for m in MARKETS}
    ev: list[dict] = []

    def credit(market, points, signal, detail):
        pts[market] += points
        ev.append({"market": market, "signal": signal, "detail": detail, "points": points})

    for name, spec in MARKETS.items():
        seen_dial = {n for n in numbers if n.startswith(spec["dial"])}
        if seen_dial:
            credit(name, min(3.0 * len(seen_dial), 6.0), "phone_country_code", f"{spec['dial']} x{len(seen_dial)}")
        if (m := re.search(spec["currency"], text, re.I)):
            credit(name, 2.0, "currency", m.group(0).strip())
        terms = {t.group(0).lower() for t in re.finditer(spec["terms"], text, re.I)}
        if terms:
            credit(name, min(2.0 * len(terms), 6.0), "place_or_operator_name", ", ".join(sorted(terms))[:80])
        if spec["payment"] and (m := re.search(spec["payment"], text, re.I)):
            credit(name, 2.0, "local_payment_method", m.group(0).strip())
        if spec.get("script") and len(re.findall(spec["script"], text)) >= 10:
            credit(name, 2.0, "script", "non-Latin script text")
        if domain and domain.endswith(spec["tld"]):
            credit(name, 1.0, "country_code_tld", spec["tld"])  # weak by design
    if _SWAHILI.search(text):
        for name in ("Kenya", "Tanzania"):
            credit(name, 0.5, "language", "Kiswahili")

    ranked = sorted(pts.items(), key=lambda kv: (-kv[1], kv[0]))
    top, second = ranked[0], ranked[1]
    strong = [m for m, p in ranked if p >= MIN_POINTS]
    if top[1] < MIN_POINTS:
        return MarketGuess("Unknown", round(min(top[1] / 10, 0.2), 2), ev, pts)
    if len(strong) >= 2 or (_GROUP.search(text) and top[1] >= MIN_POINTS):
        return MarketGuess("Multi-market / Group", round(min(0.9, 0.4 + 0.1 * len(strong)), 2),
                           [e for e in ev if e["market"] in strong], pts)
    conf = round(min(0.95, top[1] / (top[1] + second[1] + 3)), 2)
    return MarketGuess(top[0], conf, [e for e in ev if e["market"] == top[0]], pts)
