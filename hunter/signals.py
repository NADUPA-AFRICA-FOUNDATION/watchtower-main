"""Page signal extraction.

Turns a fetched page into *observations with provenance*: what was found, where, and
the surrounding text. It does not judge. Whether a combination is suspicious is the
scorer's job (Milestone 7), which reads `flags` and cites the evidence.

Rules this module holds to:
  * Form fields are classified by what they ask for (password, pin, otp, card, ...). Only
    field types and context are kept, never a value, and nothing is ever submitted.
  * Inputs outside any <form> count: phishing kits often submit with JavaScript.
  * Phrase matches near warning language ("never share your PIN") are advisory, not
    solicitations. The fixed claim in CLAUDE.md that scamscan's `pin_request` fires on that
    sentence is a known gap there; here it is handled explicitly.
  * Operator-supplied phrases are literals, never regular expressions.
  * Payment account numbers are not extracted (only the Paybill/Till identifier), to
    keep personal data out of the graph.
  * Everything extracted from a hostile page is data. Nothing is evaluated or followed.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from functools import lru_cache
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from watchtower.discovery.page_analysis import ANALYTICS_PATTERNS

from .config import FREE_HOSTING, Brand, SignalsConfig
from .market import MarketGuess, detect_market
from .normalize import (
    CRYPTO, DOMAIN, EMAIL, PAYMENT, PHONE, SOCIAL, TELEGRAM, URL, WHATSAPP,
    InvalidIndicator, normalize,
)
from .prescore import is_official, registrable

ANALYTICS = "analytics_id"
PIVOT_VALUE = {PHONE: "high", WHATSAPP: "high", TELEGRAM: "high", PAYMENT: "high", CRYPTO: "high",
               ANALYTICS: "high", EMAIL: "medium", SOCIAL: "medium", DOMAIN: "low"}

INFRA_DOMAINS = frozenset({
    "google.com", "googleapis.com", "gstatic.com", "googletagmanager.com", "google-analytics.com",
    "doubleclick.net", "cloudflare.com", "cloudflareinsights.com", "jsdelivr.net", "cdnjs.com",
    "unpkg.com", "bootstrapcdn.com", "jquery.com", "fontawesome.com", "w3.org", "schema.org",
    "gravatar.com", "wp.com", "wordpress.org", "wordpress.com", "microsoft.com", "apple.com",
    "mozilla.org", "adobe.com", "youtube.com", "youtu.be", "play.google.com",
})

_FIELD_SKIP = {"hidden", "submit", "button", "reset", "image", "checkbox", "radio", "file", "search"}
_RESOURCE_TAGS = {"script", "style", "noscript", "template"}

# -- field classification ------------------------------------------------------------------
_FIELD_RULES = (
    ("pin", re.compile(r"\b(?:m ?pesa pin|pin|secret (?:pin|number|code)|nambari ya siri|namba ya siri)\b")),
    ("otp", re.compile(r"\b(?:otp|one time (?:pin|password|code)|verification code|confirmation code|"
                       r"sms code|security code sent|one-time-code|one time code)\b")),
    ("cvv", re.compile(r"\b(?:cvv|cvc|cvv2|csc|card security|cc csc)\b")),
    ("card_number", re.compile(r"\b(?:card (?:number|no)|credit card|debit card|cc number|cc-number|pan)\b")),
    ("card_expiry", re.compile(r"\b(?:expiry|expiration|exp date|cc exp|mm yy)\b")),
    ("id_number", re.compile(r"\b(?:national id|id (?:number|no)|passport|huduma|nin|identity (?:card|number))\b")),
    ("account_number", re.compile(r"\b(?:account (?:number|no)|acc (?:number|no)|iban)\b")),
    ("phone", re.compile(r"\b(?:phone|mobile|msisdn|tel|telephone|simu|cell)\b")),
    ("email", re.compile(r"\b(?:e ?mail)\b")),
    ("full_name", re.compile(r"\b(?:full name|first name|last name|surname|your name)\b")),
    ("amount", re.compile(r"\b(?:amount|kes|ksh)\b")),
)
FIELD_TIER = {"password": "high", "pin": "high", "otp": "high", "cvv": "high", "card_number": "high",
              "id_number": "medium", "account_number": "medium", "card_expiry": "medium",
              "phone": "low", "email": "low", "full_name": "low", "amount": "low"}

# -- phrase rules ----------------------------------------------------------------------------
# name -> (category, patterns). Kiswahili entries are standard Kiswahili, not Sheng; have a
# native speaker review them before relying on them for scoring.
DEFAULT_RULES: dict[str, tuple[str, tuple[str, ...]]] = {
    "verify_account": ("credential_request", (
        r"\bverif(?:y|ication)\W+(?:of\W+)?(?:your\W+)?(?:m-?pesa\W+)?account\b", r"\baccount\W+verification\b")),
    "account_suspended": ("urgency", (
        r"\baccount\W+(?:has\W+been\W+|will\W+be\W+|is\W+)?(?:suspended|blocked|locked|deactivated|restricted|frozen)\b",
        r"\b(?:suspend|block|lock|deactivat)\w*\W+your\W+account\b")),
    "urgent_verification": ("urgency", (
        r"\burgent(?:ly)?\W+(?:action|verification|attention|update)\b",
        r"\bwithin\W+\d{1,3}\W+(?:hours?|minutes?|mins?)\b", r"\bimmediate(?:ly)?\W+(?:action|verification)\b")),
    "claim_reward": ("reward", (
        r"\bclaim\W+(?:your\W+)?(?:reward|prize|bonus|gift|cash)\b",
        r"\byou(?:'ve|\W+have)\W+(?:won|been\W+selected)\b", r"\bcongratulations\b")),
    "loan_approved": ("reward", (
        r"\bloan\W+(?:has\W+been\W+|is\W+)?(?:approved|pre-?approved)\b", r"\b(?:instant|quick|fast)\W+loan\b",
        r"\bpre-?qualified\b")),
    "activation_fee": ("fee", (
        r"\b(?:activation|registration|processing|verification|clearance|withdrawal|release|insurance|unlock)\W+(?:fee|charge)s?\b",
        r"\bpay\W+(?:a\W+)?(?:small\W+)?(?:fee|charge)\W+(?:to|before)\b")),
    "unlock_account": ("credential_request", (r"\bunlock\W+(?:your\W+)?(?:m-?pesa\W+)?account\b", r"\baccount\W+unlock\b")),
    "confirm_pin": ("credential_request", (
        r"\b(?:confirm|enter|provide|send|share|verify|update|reset)\W+(?:your\W+)?(?:m-?pesa\W+)?pin\b",)),
    "enter_otp": ("credential_request", (
        r"\b(?:enter|provide|send|share|input|type)\W+(?:the\W+|your\W+)?(?:otp|one[- ]time\W+(?:pin|password|code)|"
        r"verification\W+code|confirmation\W+code)\b",)),
    "customer_support": ("contact", (r"\bcustomer\W+(?:care|support|service)\b", r"\bhelp\W*desk\b")),
    "contact_whatsapp": ("contact", (
        r"\b(?:contact|chat|message|reach|text|whatsapp)\W+(?:us\W+)?(?:on|via|through|at)\W+whats\W?app\b",
        r"\bwhats\W?app\W+(?:us|support|agent|customer)\b")),
    "contact_telegram": ("contact", (
        r"\b(?:contact|chat|message|reach|text)\W+(?:us\W+)?(?:on|via|through|at)\W+telegram\b",
        r"\btelegram\W+(?:us|support|agent|channel)\b")),
    "guaranteed_returns": ("investment", (
        r"\bguarantee[d]?\W+(?:returns?|profits?|income|roi)\b",
        r"\b\d{1,3}\W*(?:%|percent)\W+(?:daily|weekly|monthly)\W+(?:returns?|profit|interest|roi)\b",
        r"\brisk\W+free\b")),
    "double_money": ("investment", (r"\bdouble\W+(?:your\W+)?(?:money|investment|funds|cash)\b",
                                    r"\b(?:triple|10x)\W+your\b")),
    "investment_opportunity": ("investment", (
        r"\binvestment\W+(?:opportunity|plan|package|scheme)\b", r"\b(?:invest|deposit)\W+(?:and|&)\W+(?:earn|get|receive)\b",
        r"\bpassive\W+income\b")),
    "payment_instruction": ("payment", (
        r"\b(?:send|pay|deposit|transfer)\W+(?:kes|ksh|kshs|tsh|usd|\$)?\W*[\d,.]{2,}\W+(?:to|via)\b",
        r"\b(?:paybill|pay\W?bill|till|buy\W+goods)\W+(?:number|no)?\W*\d{5,7}\b")),
    # Kiswahili
    "sw_verify_account": ("credential_request", (r"\bthibitisha\W+(?:akaunti|account)\b",)),
    "sw_enter_pin": ("credential_request", (r"\b(?:ingiza|weka)\W+(?:namba|nambari)?\W*(?:ya\W+siri|pin)\b",)),
    "sw_won": ("reward", (r"\bumeshinda\b", r"\bzawadi\W+yako\b")),
    "sw_fee": ("fee", (r"\bada\W+ya\W+(?:usajili|kuanzisha|uthibitisho)\b",)),
    "sw_loan_approved": ("reward", (r"\bmkopo\W+(?:wako\W+)?(?:umeidhinishwa|umepitishwa)\b",)),
}
# Local (per-match) demotion uses negation only. Softer words ("beware", "warning", "phishing")
# are cheap for an attacker to sprinkle next to a lure, so they only count at page level, and
# only when the page asks for no credentials (see `quoting` below).
_NEGATION = re.compile(r"\b(?:never|do\s+not|don'?t|not\s+to|hatutawahi|usishiriki)\b", re.I)
# "warning" and "security alert" are left out on purpose: phishing pages title themselves that way.
_ADVISORY_TITLE = re.compile(r"\b(?:scam\w*|fraud\w*|phishing|beware|advisory|how\s+to\s+(?:spot|avoid))\b", re.I)
_ADVISORY_WINDOW = 120


@lru_cache(maxsize=16)
def compile_rules(extra: tuple, disabled: tuple) -> dict:
    """name -> (category, [compiled]). `extra` is a tuple of (rule, tuple_of_literals)."""
    rules = {n: (cat, [re.compile(p, re.I) for p in pats]) for n, (cat, pats) in DEFAULT_RULES.items()
             if n not in disabled}
    for name, phrases in extra:
        if name in disabled:
            continue
        compiled = []
        for phrase in phrases:
            tokens = re.findall(r"\w+", phrase.lower())
            if tokens:
                compiled.append(re.compile(r"\b" + r"\W+".join(map(re.escape, tokens)) + r"\b", re.I))
        cat, existing = rules.get(name, ("custom", []))
        rules[name] = (cat, [*existing, *compiled])
    return rules


# -- HTML structure -----------------------------------------------------------------------------
class _Doc(HTMLParser):
    def __init__(self, base: str):
        super().__init__(convert_charrefs=True)
        self.base = base
        self.title: list[str] = []
        self.headings: list[str] = []
        self.text: list[str] = []
        self.anchors: list[dict] = []
        self.iframes: list[str] = []
        self.inline_scripts: list[str] = []
        self.forms: list[dict] = []
        self.meta_refresh: str | None = None
        self._skip = 0
        self._title = self._heading = False
        self._a: dict | None = None
        self._form: dict | None = None
        self._script: list[str] | None = None
        self._label: dict | None = None
        self._labels_for: dict[str, str] = {}
        self._loose: dict = {"action": None, "method": "", "fields": [], "text": [], "hidden": 0, "formless": True}

    def handle_starttag(self, tag, attrs):
        a = {k: (v or "") for k, v in attrs}
        if tag in _RESOURCE_TAGS:
            self._skip += 1
            if tag == "script" and not a.get("src"):
                self._script = []
        elif tag == "title":
            self._title = True
        elif tag in {"h1", "h2", "h3"}:
            self._heading = True
        elif tag == "meta" and a.get("http-equiv", "").lower() == "refresh":
            m = re.search(r"url\s*=\s*['\"]?([^'\";\s]+)", a.get("content", ""), re.I)
            if m:
                self.meta_refresh = urljoin(self.base, m.group(1))
        elif tag == "a" and a.get("href"):
            self._a = {"href": urljoin(self.base, a["href"]), "raw": a["href"], "text": []}
        elif tag == "iframe" and a.get("src"):
            self.iframes.append(urljoin(self.base, a["src"]))
        elif tag == "form":
            self._form = {"action": urljoin(self.base, a["action"]) if a.get("action") else None,
                          "method": a.get("method", "get").lower() or "get", "fields": [], "text": [], "hidden": 0,
                          "formless": False}
            self.forms.append(self._form)
        elif tag == "label":
            self._label = {"for": a.get("for", ""), "text": [], "fields": []}
        elif tag in {"input", "select", "textarea"}:
            kind = a.get("type", "text").lower() if tag == "input" else tag
            target = self._form if self._form is not None else self._loose
            if kind == "hidden":
                target["hidden"] += 1
            elif kind not in _FIELD_SKIP:
                f = {"tag": tag, "type": kind, "name": a.get("name", ""), "id": a.get("id", ""),
                     "placeholder": a.get("placeholder", ""), "autocomplete": a.get("autocomplete", ""),
                     "inputmode": a.get("inputmode", ""), "maxlength": a.get("maxlength", ""),
                     "aria": a.get("aria-label", ""), "title": a.get("title", ""), "label": ""}
                target["fields"].append(f)
                if self._label is not None:
                    self._label["fields"].append(f)

    def handle_endtag(self, tag):
        if tag in _RESOURCE_TAGS:
            self._skip = max(0, self._skip - 1)
            if tag == "script" and self._script is not None:
                self.inline_scripts.append("".join(self._script)[:20000])
                self._script = None
        elif tag == "title":
            self._title = False
        elif tag in {"h1", "h2", "h3"}:
            self._heading = False
        elif tag == "a" and self._a is not None:
            self._a["text"] = " ".join("".join(self._a["text"]).split())[:120]
            self.anchors.append(self._a)
            self._a = None
        elif tag == "form":
            self._form = None
        elif tag == "label" and self._label is not None:
            text = " ".join("".join(self._label["text"]).split())[:120]
            if self._label["for"]:
                self._labels_for[self._label["for"]] = text
            for f in self._label["fields"]:
                f["label"] = text
            self._label = None

    def handle_data(self, data):
        if self._script is not None:
            self._script.append(data)
            return
        if self._skip:
            return
        value = " ".join(data.split())
        if not value:
            return
        self.text.append(value)
        if self._title:
            self.title.append(value)
        if self._heading:
            self.headings.append(value)
        if self._a is not None:
            self._a["text"].append(data)
        if self._label is not None:
            self._label["text"].append(data)
        (self._form if self._form is not None else self._loose)["text"].append(value)

    def finish(self) -> None:
        for form in [*self.forms, self._loose]:
            for f in form["fields"]:
                if not f["label"] and f["id"] in self._labels_for:
                    f["label"] = self._labels_for[f["id"]]
        if self._loose["fields"]:
            self.forms.append(self._loose)


def _words(s: str) -> str:
    s = re.sub(r"([a-z])([A-Z])", r"\1 \2", s)          # mpesaPin -> mpesa Pin
    return " ".join(re.sub(r"[_\-.\[\]:/]+", " ", s).lower().split())


def classify_field(f: dict) -> set[str]:
    cats: set[str] = set()
    if f["type"] == "password":
        cats.add("password")
    blob = _words(" ".join([f["name"], f["id"], f["placeholder"], f["aria"], f["title"], f["label"], f["autocomplete"]]))
    for cat, pattern in _FIELD_RULES:
        if pattern.search(blob):
            cats.add(cat)
    if f["type"] == "tel":
        cats.add("phone")
    if f["type"] == "email":
        cats.add("email")
    if f["autocomplete"] == "one-time-code":
        cats.add("otp")
    # A masked short numeric box is a PIN/OTP even when its name is "field1".
    if (f["type"] == "password" and f["maxlength"].isdigit() and int(f["maxlength"]) <= 6) or \
            (f["inputmode"] == "numeric" and f["maxlength"].isdigit() and 4 <= int(f["maxlength"]) <= 8
             and f["type"] in {"password", "text", "number", "tel"} and not cats - {"phone"}):
        cats.add("pin" if f["type"] == "password" else "otp")
    return cats


# -- result types ---------------------------------------------------------------------------------
@dataclass
class SignalIndicator:
    type: str
    canonical: str
    original: str
    where: list
    snippet: str
    confidence: float
    pivot_value: str
    meta: dict = field(default_factory=dict)

    def facts(self) -> dict:
        return {"type": self.type, "canonical": self.canonical, "where": sorted(self.where),
                "snippet": self.snippet, "confidence": self.confidence, "pivot_value": self.pivot_value,
                **({"meta": self.meta} if self.meta else {})}


@dataclass
class PageSignals:
    url: str
    brand: dict = field(default_factory=dict)
    indicators: list = field(default_factory=list)
    forms: list = field(default_factory=list)
    phrases: list = field(default_factory=list)
    external_links: list = field(default_factory=list)
    official_links: list = field(default_factory=list)
    js_redirects: list = field(default_factory=list)
    meta_refresh: str | None = None
    unassessed_reason: str | None = None
    advisory_context: bool = False
    market: MarketGuess | None = None
    flags: dict = field(default_factory=dict)

    def facts(self) -> dict:
        return {
            "url": self.url, "brand": self.brand, "flags": dict(sorted(self.flags.items())),
            "indicators": [i.facts() for i in sorted(self.indicators, key=lambda i: (i.type, i.canonical))],
            "forms": self.forms, "phrases": self.phrases, "external_links": self.external_links,
            "official_links": self.official_links, "js_redirects": self.js_redirects,
            "meta_refresh": self.meta_refresh, "unassessed_reason": self.unassessed_reason,
            "advisory_context": self.advisory_context,
            "market": self.market.facts() if self.market else None,
        }


# -- extraction ---------------------------------------------------------------------------------
def snip(text: str, start: int, end: int, n: int) -> str:
    pad = max((n - (end - start)) // 2, 10)
    return " ".join(text[max(start - pad, 0): end + pad].split())[:n]


def alias_regex(alias: str) -> re.Pattern | None:
    chars = [c for c in unicodedata.normalize("NFKC", alias.lower()) if c.isalnum()]
    if not chars:
        return None
    sep = r"[\s‐-―\-_.]?"
    return re.compile(r"(?<![a-z0-9])" + sep.join(map(re.escape, chars)) + r"(?![a-z0-9])", re.I)


_TEXT_PHONE = re.compile(
    r"(?<![\w.+])(?:\+|00)\d{1,3}[\s().-]?\d(?:[\s().-]?\d){7,11}(?!\w)|(?<![\w.+])0[17]\d(?:[\s.-]?\d){7}(?!\d)")
_TEXT_EMAIL = re.compile(r"(?<![\w.+-])[a-z0-9._%+-]{1,64}@[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,24}(?![\w-])", re.I)
_TEXT_URL = re.compile(r"https?://[^\s<>\"')]{4,300}", re.I)
_TEXT_HANDLE = re.compile(r"(?<![\w@])@([A-Za-z][A-Za-z0-9_]{4,31})\b")
_PAYBILL = re.compile(r"\b(?:pay\s?bill|business\s*(?:no|number))\b\D{0,20}?(\d{5,7})\b", re.I)
_TILL = re.compile(r"\b(?:till|buy\s?goods)\b(?:\W+(?:no|number))?\D{0,15}?(\d{5,7})\b", re.I)
_CRYPTO_STRONG = re.compile(r"\b(?:0x[0-9a-fA-F]{40}|bc1[ac-hj-np-z02-9]{11,71})\b")
_CRYPTO_WEAK = re.compile(r"(?<![A-Za-z0-9])(?:T[1-9A-HJ-NP-Za-km-z]{33}|[13][1-9A-HJ-NP-Za-km-z]{25,34})(?![A-Za-z0-9])")
_CRYPTO_CONTEXT = re.compile(r"wallet|address|bitcoin|btc|eth|usdt|trc-?20|erc-?20|crypto|deposit|send\s+to", re.I)
_JS_REDIRECT = re.compile(r"""(?:window\.|document\.|top\.)?location(?:\.href|\.replace\s*\(|\.assign\s*\(|\s*=)\s*=?\s*\(?\s*['"]([^'"]{4,300})['"]""")
_FILE_TLDS = {"png", "jpg", "jpeg", "gif", "svg", "webp", "css", "js", "ico", "woff", "woff2"}
_WA_NEAR = re.compile(r"whats\s?app", re.I)


class _Collector:
    def __init__(self, cfg: SignalsConfig):
        self.cfg = cfg
        self.items: dict[tuple, SignalIndicator] = {}
        self.skipped = 0

    def add(self, ind, where: str, snippet: str, confidence: float, **meta):
        key = (ind.type, ind.canonical)
        pivot = meta.pop("pivot_value", None) or PIVOT_VALUE.get(ind.type, "low")
        cur = self.items.get(key)
        if cur is None:
            self.items[key] = SignalIndicator(ind.type, ind.canonical, ind.original, [where],
                                              snippet[:self.cfg.snippet_chars], confidence, pivot, meta)
            return
        if where not in cur.where:
            cur.where.append(where)
        if confidence > cur.confidence:
            cur.confidence, cur.snippet = confidence, snippet[:self.cfg.snippet_chars]
        if _RANK[pivot] > _RANK[cur.pivot_value]:
            cur.pivot_value = pivot


_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3}


def _is_infra(host: str, cfg: SignalsConfig) -> bool:
    reg = registrable(host)
    return reg in INFRA_DOMAINS or reg in set(cfg.infrastructure_domains) or host in INFRA_DOMAINS


def extract_signals(page, brand: Brand, cfg: SignalsConfig) -> PageSignals:
    """`page` is a hunter.acquire.Page with `html` still attached."""
    url = page.final_url or page.requested_url
    doc = _Doc(url)
    try:
        doc.feed(page.html or "")
        doc.close()
    except Exception:  # hostile markup: keep whatever parsed
        pass
    doc.finish()
    text = unicodedata.normalize("NFKC", " ".join(doc.text))[:cfg.text_cap]
    title = " ".join(doc.title)
    out = PageSignals(url, meta_refresh=doc.meta_refresh, unassessed_reason=getattr(page, "unassessed_reason", None))
    here = registrable(urlsplit(url).hostname or "")
    col = _Collector(cfg)
    n = cfg.snippet_chars

    # -- brand ----------------------------------------------------------------------------
    brand_terms, related_terms, body_hits, form_hits = set(), set(), 0, 0
    form_text = " ".join(" ".join(f["text"]) for f in doc.forms)
    for alias in brand.aliases:
        rx = alias_regex(alias)
        if rx and (found := list(rx.finditer(text))):
            brand_terms.add(alias)
            body_hits += len(found)
            form_hits += len(rx.findall(unicodedata.normalize("NFKC", form_text)))
    for alias in brand.related_brands:
        rx = alias_regex(alias)
        if rx and rx.search(text):
            related_terms.add(alias)
    heads = " ".join(doc.headings)
    out.brand = {
        "terms": sorted(brand_terms), "related_terms": sorted(related_terms),
        "in_title": any((r := alias_regex(a)) and r.search(title) for a in brand.aliases),
        "in_headings": any((r := alias_regex(a)) and r.search(heads) for a in brand.aliases),
        "body_mentions": body_hits, "form_mentions": form_hits,
    }

    # -- advisory context -------------------------------------------------------------------
    out.advisory_context = bool(_ADVISORY_TITLE.search(title + " " + heads + " " + text[:300]))

    # -- links ----------------------------------------------------------------------------
    def handle_url(href: str, where: str, label: str, forced_pivot: str | None = None):
        try:
            ind = normalize(href)
        except InvalidIndicator:
            return
        if ind.type in {WHATSAPP, TELEGRAM, SOCIAL, EMAIL, PHONE}:
            col.add(ind, where, label or href, 0.95 if where in {"link", "tel_link", "mailto_link"} else 0.8)
            return
        host = ind.meta.get("host") if ind.type == URL else ind.canonical
        if not host:
            return
        if is_official(host, brand):
            if len(out.official_links) < 10 and host not in out.official_links:
                out.official_links.append(host)
            return
        if registrable(host) == here:
            return
        shared = any(host.endswith("." + h) for h in FREE_HOSTING)
        reg = host if shared else registrable(host)
        category = "infrastructure" if _is_infra(host, cfg) else "external"
        entry = {"host": reg, "where": where, "label": (label or "")[:80], "category": category}
        if entry not in out.external_links and len(out.external_links) < 100:
            out.external_links.append(entry)
        if category == "external":
            pay = bool(re.search(r"pay|login|verify|claim|account|loan|invest|withdraw", label or "", re.I))
            pivot = forced_pivot or ("medium" if pay or where == "iframe" else "low")
            col.add(normalize(reg, hint="domain"), where, label or href, 0.7, pivot_value=pivot)

    for a in doc.anchors:
        raw = a["raw"].strip()
        where = "tel_link" if raw.lower().startswith("tel:") else "mailto_link" if raw.lower().startswith("mailto:") else "link"
        handle_url(raw if where != "link" else a["href"], where, a["text"])
    for src in doc.iframes:
        handle_url(src, "iframe", "")
    if doc.meta_refresh:
        handle_url(doc.meta_refresh, "meta_refresh", "", "high")
    for script in doc.inline_scripts:
        for m in _JS_REDIRECT.finditer(script):
            target = urljoin(url, m.group(1))
            if urlsplit(target).scheme in {"http", "https"} and target not in out.js_redirects:
                out.js_redirects.append(target)
                handle_url(target, "js_redirect", "", "high")
        for m in _TEXT_URL.finditer(script):
            if re.search(r"wa\.me|whatsapp|t\.me|telegram", m.group(0), re.I):
                handle_url(m.group(0), "script", "")

    # -- text indicators ----------------------------------------------------------------------
    for m in _TEXT_URL.finditer(text):
        handle_url(m.group(0).rstrip(".,;:!"), "text", snip(text, m.start(), m.end(), n))
    for m in _TEXT_PHONE.finditer(text):
        try:
            ind = normalize(m.group(0), hint="phone", region=cfg.default_region)
        except InvalidIndicator:
            col.skipped += 1
            continue
        s = snip(text, m.start(), m.end(), n)
        col.add(ind, "text", s, 0.7)
        if _WA_NEAR.search(text[max(m.start() - 50, 0): m.end() + 30]):
            wa = normalize(ind.canonical, hint="whatsapp")
            col.add(wa, "text_near_whatsapp", s, 0.75)
    for m in _TEXT_EMAIL.finditer(text):
        if m.group(0).rsplit(".", 1)[-1].lower() in _FILE_TLDS:
            continue
        try:
            col.add(normalize(m.group(0), hint="email"), "text", snip(text, m.start(), m.end(), n), 0.7)
        except InvalidIndicator:
            col.skipped += 1
    for m in _TEXT_HANDLE.finditer(text):
        window = text[max(m.start() - 40, 0): m.end() + 10]
        if re.search(r"telegram|t\.me", window, re.I):
            try:
                col.add(normalize(m.group(1), hint="telegram"), "text_near_telegram", snip(text, m.start(), m.end(), n), 0.7)
            except InvalidIndicator:
                col.skipped += 1
    for rx, label in ((_PAYBILL, "Paybill"), (_TILL, "Till")):
        for m in rx.finditer(text):
            # Only the matched span: padding could pull in the account number beside it.
            col.add(normalize(f"{label} {m.group(1)}", hint="payment"), "text", " ".join(m.group(0).split())[:n], 0.85,
                    account_number_captured=False)
    for rx, needs_ctx in ((_CRYPTO_STRONG, False), (_CRYPTO_WEAK, True)):
        for m in rx.finditer(text):
            if needs_ctx and not _CRYPTO_CONTEXT.search(text[max(m.start() - 60, 0): m.start()]):
                continue
            try:
                col.add(normalize(m.group(0), hint="crypto"), "text", snip(text, m.start(), m.end(), n), 0.85)
            except InvalidIndicator:
                col.skipped += 1
    html = page.html or ""
    for kind, rx in ANALYTICS_PATTERNS.items():
        for found in rx.findall(html):
            value = found if isinstance(found, str) else found[0]
            from .normalize import Indicator
            col.add(Indicator(ANALYTICS, f"{kind}:{str(value).lower()}", str(value)), "html", f"{kind} {value}", 0.9)

    # -- forms ----------------------------------------------------------------------------------
    for form in doc.forms[:20]:
        fields = []
        for f in form["fields"][:40]:
            cats = classify_field(f)
            fields.append({"type": f["type"], "name": f["name"][:60], "label": f["label"][:80],
                           "placeholder": f["placeholder"][:80], "categories": sorted(cats)})
        solicits = sorted({c for f in fields for c in f["categories"]})
        action = form["action"]
        action_host = (urlsplit(action).hostname or "").lower() if action else ""
        cross = bool(action_host) and registrable(action_host) != here
        if cross and not is_official(action_host, brand):
            handle_url(action, "form_action", "", "high")
        out.forms.append({
            "method": form["method"], "action": action, "formless": form["formless"],
            "action_host": action_host or None, "cross_origin": cross,
            "insecure_post": bool(action and action.startswith("http://") and url.startswith("https://")),
            "hidden_fields": form["hidden"], "fields": fields, "solicits": solicits,
            "high_sensitivity": sorted(set(solicits) & {c for c, t in FIELD_TIER.items() if t == "high"}),
            "context": " ".join(form["text"])[:200],
        })

    # -- phrases ------------------------------------------------------------------------------------
    # A page about scams that asks for no credentials is quoting the bait, not using it. With a
    # credential form present, the advisory words prove nothing (an attacker can add them).
    quoting = out.advisory_context and not any(f["high_sensitivity"] for f in out.forms)
    rules = compile_rules(tuple(sorted((k, tuple(v)) for k, v in cfg.phrases.items())), tuple(sorted(cfg.disable)))
    for name, (category, patterns) in sorted(rules.items()):
        hits, advisory = 0, 0
        snippets: list[str] = []
        for rx in patterns:
            for m in rx.finditer(text):
                window = text[max(m.start() - _ADVISORY_WINDOW, 0): m.end() + _ADVISORY_WINDOW]
                if quoting or _NEGATION.search(window):
                    advisory += 1
                    continue
                hits += 1
                if len(snippets) < cfg.max_snippets:
                    snippets.append(snip(text, m.start(), m.end(), n))
        if hits or advisory:
            out.phrases.append({"rule": name, "category": category, "count": hits, "advisory_count": advisory,
                                "snippets": snippets})

    # -- aggregate ----------------------------------------------------------------------------------
    out.indicators = list(col.items.values())
    out.market = detect_market(text, [i.canonical for i in out.indicators if i.type in {PHONE, WHATSAPP}
                                      and i.canonical.startswith("+")], urlsplit(url).hostname or "")
    fired = {p["rule"] for p in out.phrases if p["count"]}
    types = {i.type for i in out.indicators}
    solicited = {c for f in out.forms for c in f["solicits"]}
    out.flags = {
        "brand_mentioned": bool(out.brand["terms"]),
        "brand_in_title": out.brand["in_title"],
        "credential_form": any(f["high_sensitivity"] for f in out.forms),
        "solicits_pin": "pin" in solicited,
        "solicits_otp": "otp" in solicited,
        "solicits_card": bool(solicited & {"card_number", "cvv"}),
        "solicits_id": "id_number" in solicited,
        "formless_credential_inputs": any(f["formless"] and f["high_sensitivity"] for f in out.forms),
        "cross_origin_form": any(f["cross_origin"] for f in out.forms if f["solicits"]),
        # An advisory that asks for nothing is quoting indicators, not directing anyone to them.
        "whatsapp_cta": (WHATSAPP in types and not quoting) or "contact_whatsapp" in fired,
        "telegram_cta": (TELEGRAM in types and not quoting) or "contact_telegram" in fired,
        "payment_instruction": (PAYMENT in types and not quoting) or "payment_instruction" in fired,
        "crypto_wallet": CRYPTO in types and not quoting,
        "quoting_advisory": quoting,
        "fee_language": bool(fired & {"activation_fee", "sw_fee"}),
        "guaranteed_returns": bool(fired & {"guaranteed_returns", "double_money"}),
        "credential_language": bool({p["rule"] for p in out.phrases if p["count"] and p["category"] == "credential_request"}),
        "urgency_language": bool(fired & {"account_suspended", "urgent_verification"}),
        "reward_language": bool({p["rule"] for p in out.phrases if p["count"] and p["category"] == "reward"}),
        "advisory_context": out.advisory_context,
        "redirects_elsewhere": bool(out.js_redirects or out.meta_refresh),
        "official_link_present": bool(out.official_links),
        "content_unassessed": bool(out.unassessed_reason),
    }
    return out
