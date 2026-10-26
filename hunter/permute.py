"""Bounded impersonation-domain generator.

Generates label variants from a brand's aliases, crosses them with a short list
of TLDs, ranks them with the pre-scorer, and keeps only the top N. Nothing here
resolves a name: these are candidates to check, not findings. The bounds
(`max_labels`, `max_tlds_per_label`, `max_candidates`) exist so a long alias list
can never turn into millions of lookups.

Output is deterministic: equal scores are broken alphabetically, so the same
config yields the same list run to run and a test can pin it.
"""
from __future__ import annotations

from dataclasses import dataclass

from .config import MARKET_TOKENS, Brand, HuntConfig
from .prescore import PreScore, is_official, plain, prescore

AFFIXES = (
    "login", "secure", "support", "verify", "account", "customer", "help", "pay", "loan", "loans",
    "credit", "invest", "investment", "reward", "promo", "offer", "registration", "update",
    "portal", "service", "care", "wallet", "activate", "kyc", "bonus", "giveaway",
)

_HOMOGLYPH = {"o": "0", "l": "1", "i": "1", "e": "3", "a": "4", "s": "5", "t": "7"}
_VOWELS = "aeiou"
_DRAW = {"affix": 4, "market": 2}


@dataclass
class Permutation:
    domain: str
    kind: str
    label: str
    prescore: PreScore


def _edits(word: str) -> dict[str, str]:
    """Single-edit variants of `word`, label -> edit kind."""
    out: dict[str, str] = {}
    n = len(word)
    for i in range(n):
        out.setdefault(word[:i] + word[i + 1:], "omission")
        out.setdefault(word[:i + 1] + word[i] + word[i + 1:], "duplication")
        if i < n - 1:
            out.setdefault(word[:i] + word[i + 1] + word[i] + word[i + 2:], "transposition")
        if word[i] in _HOMOGLYPH:
            out.setdefault(word[:i] + _HOMOGLYPH[word[i]] + word[i + 1:], "homoglyph")
        if word[i] in _VOWELS:
            for v in _VOWELS:
                if v != word[i]:
                    out.setdefault(word[:i] + v + word[i + 1:], "vowel_swap")
        if word[i] == "m":
            out.setdefault(word[:i] + "rn" + word[i + 1:], "homoglyph")
    return {k: v for k, v in out.items() if len(k) >= 3 and k != word}


def _hyphenated(alias: str) -> list[str]:
    """`m-pesa` and `mpesa` are both worth generating from either spelling."""
    flat = plain(alias)
    forms = {flat, alias.lower().replace(" ", "-")}
    if len(flat) >= 4 and "-" not in alias:
        forms.add(flat[0] + "-" + flat[1:])  # m-pesa style split after the first letter
    return sorted(f for f in forms if f)


def _market_tokens(brand: Brand) -> list[str]:
    tokens: list[str] = []
    for m in brand.markets or list(MARKET_TOKENS):
        tokens.extend(MARKET_TOKENS.get(m.lower(), [plain(m)]))
    return sorted(dict.fromkeys(tokens))


def generate_labels(brand: Brand, limit: int) -> dict[str, str]:
    """label -> generation kind, capped at `limit` (shortest, simplest labels first)."""
    labels: dict[str, str] = {}
    markets = _market_tokens(brand)

    def put(label: str, kind: str):
        label = label.strip("-")
        if 3 <= len(label) <= 63 and label not in labels:
            labels[label] = kind

    for alias in brand.aliases:
        for base in _hyphenated(alias):
            flat = plain(base)
            put(base, "base")
            for word in AFFIXES:
                put(f"{base}-{word}", "affix")
                put(f"{word}-{base}", "affix")
                put(f"{flat}{word}", "affix")
                put(f"{word}{flat}", "affix")
            for tok in markets:
                put(f"{base}-{tok}", "market")
                put(f"{flat}{tok}", "market")
            for edited, kind in _edits(flat).items():
                put(edited, kind)
                put(f"{edited}-login", kind)
                put(f"{edited}-secure", kind)
            put(flat[::-1], "reversed")
            if "-" in base:
                put("-".join(reversed(base.split("-"))), "reversed")
            if len(labels) >= limit * 2:
                break
    ordered = sorted(labels.items(), key=lambda kv: (len(kv[0]), kv[0]))
    return dict(ordered[:limit])


def _select_labels(brand: Brand, config: HuntConfig, n: int) -> list[tuple[str, str]]:
    """Best `n` labels, interleaved across variant kinds.

    Ranked on a TLD-neutral score first: a TLD bonus must not let one label's
    six spellings crowd out every other label, and equal scores must not let
    the shortest affixes starve the typo variants.
    """
    by_kind: dict[str, list[tuple[float, int, str]]] = {}
    for label, kind in generate_labels(brand, config.permutations.max_labels).items():
        score = prescore(f"{label}.com", brand, config.prescore).score
        by_kind.setdefault(kind, []).append((-score, len(label), label))
    queues = {k: sorted(v) for k, v in sorted(by_kind.items())}
    picked: list[tuple[str, str]] = []
    while len(picked) < n and any(queues.values()):
        for kind, queue in queues.items():
            # Real phishing names are overwhelmingly brand+word, so those draw more.
            for _ in range(_DRAW.get(kind, 1)):
                if queue and len(picked) < n:
                    picked.append((queue.pop(0)[2], kind))
    return picked


def generate(brand: Brand, config: HuntConfig, limit: int | None = None) -> list[Permutation]:
    cfg = config.permutations
    limit = cfg.max_candidates if limit is None else limit
    tlds = cfg.tlds[: cfg.max_tlds_per_label]
    ranked: list[Permutation] = []
    seen: set[str] = set()
    for label, kind in _select_labels(brand, config, max(1, -(-limit // max(len(tlds), 1)))):
        for tld in tlds:
            domain = f"{label}.{tld}"
            if domain in seen or is_official(domain, brand):
                continue
            seen.add(domain)
            ranked.append(Permutation(domain, kind, label, prescore(domain, brand, config.prescore)))
    ranked.sort(key=lambda p: (-p.prescore.score, len(p.domain), p.domain))
    return ranked[:limit]
