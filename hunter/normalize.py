"""Indicator normalization.

Every function either returns a canonical Indicator or raises InvalidIndicator
with a reason. Nothing returns None on failure: a value the hunter could not
parse must be visible as a rejection, not vanish as an empty result.

Canonical forms are what dedup keys on, so the original spelling is kept on the
Indicator for evidence but never used for identity.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import parse_qs, unquote, urlsplit, urlunsplit

# These names line up with investigation.models.EntityType so a candidate maps
# onto a graph entity with the same stable id.
DOMAIN = "domain"
URL = "url"
EMAIL = "email"
PHONE = "phone_number"
WHATSAPP = "whatsapp"
TELEGRAM = "telegram"
IP = "ip_address"
SOCIAL = "social_account"
PAYMENT = "payment_identifier"
CRYPTO = "crypto_wallet"

INDICATOR_TYPES = (DOMAIN, URL, EMAIL, PHONE, WHATSAPP, TELEGRAM, IP, SOCIAL, PAYMENT, CRYPTO)


class InvalidIndicator(ValueError):
    pass


@dataclass(frozen=True)
class Indicator:
    type: str
    canonical: str
    original: str
    meta: dict = field(default_factory=dict, compare=False)


_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
_TLD = re.compile(r"^([a-z]{2,63}|xn--[a-z0-9-]{1,59})$")
_EMAIL = re.compile(r"^[a-z0-9._%+'\-]{1,64}@([^@\s]+)$")
_PRIVATE_SUFFIXES = (".local", ".localhost", ".internal", ".lan", ".home.arpa", ".intranet")

_BASE58 = "[1-9A-HJ-NP-Za-km-z]"
_CRYPTO = (
    ("evm", re.compile(r"^0x[0-9a-fA-F]{40}$")),
    ("btc", re.compile(r"^bc1[ac-hj-np-z02-9]{11,71}$", re.I)),
    ("tron", re.compile(rf"^T{_BASE58}{{33}}$")),
    ("btc", re.compile(rf"^[13]{_BASE58}{{25,34}}$")),
)

_TG_HANDLE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{4,31}$")
_TG_RESERVED = {
    "share", "addstickers", "addemoji", "addtheme", "proxy", "socks", "login",
    "setlanguage", "iv", "c", "bg", "confirmphone", "invoice", "boost",
}
_WA_HOSTS = {"wa.me", "api.whatsapp.com", "web.whatsapp.com", "whatsapp.com", "www.whatsapp.com"}
_TG_HOSTS = {"t.me", "telegram.me", "telegram.dog"}

# host -> platform. Extracting a link found on a page is not crawling the platform.
_SOCIAL_HOSTS = {
    "facebook.com": "facebook", "m.facebook.com": "facebook", "web.facebook.com": "facebook",
    "fb.com": "facebook", "instagram.com": "instagram", "x.com": "x", "twitter.com": "x",
    "mobile.twitter.com": "x", "tiktok.com": "tiktok", "youtube.com": "youtube",
    "m.youtube.com": "youtube", "linkedin.com": "linkedin",
}
_SOCIAL_RESERVED = {
    "share", "sharer", "sharer.php", "dialog", "login", "plugins", "intent", "home",
    "hashtag", "explore", "search", "watch", "results", "i", "policies", "help",
    "about", "privacy", "tr", "l.php", "p", "reel", "reels", "stories", "video",
}

_PAYMENT = re.compile(r"^(paybill|pay\s*bill|till|buy\s*goods)\b\D{0,20}?(\d{5,7})\b", re.I)


def _strip(value: str) -> str:
    if not isinstance(value, str):
        raise InvalidIndicator("indicator must be a string")
    s = value.strip().strip("<>\"'").strip()
    if not s:
        raise InvalidIndicator("empty indicator")
    return s


def _host(host: str) -> str:
    host = host.strip().lower().rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    if not host:
        raise InvalidIndicator("missing hostname")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise InvalidIndicator(f"invalid IDN hostname: {host}") from exc
    return host


def _valid_domain(host: str) -> str:
    if len(host) > 253 or "." not in host:
        raise InvalidIndicator(f"not a fully qualified domain: {host}")
    labels = host.split(".")
    if not all(_LABEL.match(x) for x in labels) or not _TLD.match(labels[-1]):
        raise InvalidIndicator(f"invalid domain: {host}")
    return host


# --- individual types -------------------------------------------------------

def domain(value: str, **_) -> Indicator:
    s = _strip(value)
    parsed = urlsplit(s if "://" in s else "//" + s)
    try:
        raw_host = parsed.hostname or ""
    except ValueError as exc:
        raise InvalidIndicator(f"invalid domain: {s}") from exc
    try:
        ipaddress.ip_address(raw_host)
    except ValueError:
        return Indicator(DOMAIN, _valid_domain(_host(raw_host)), value)
    raise InvalidIndicator("an IP address is not a domain")


def url(value: str, **_) -> Indicator:
    s = _strip(value)
    parsed = urlsplit(s if "://" in s else "https://" + s)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise InvalidIndicator("only HTTP(S) URLs are supported")
    try:
        raw_host, port = parsed.hostname or "", parsed.port
    except ValueError as exc:
        raise InvalidIndicator(f"invalid URL: {s}") from exc
    try:
        host = str(ipaddress.ip_address(raw_host))
        netloc = f"[{host}]" if ":" in host else host
    except ValueError:
        host = _valid_domain(_host(raw_host))
        netloc = host
    if port not in (None, 80, 443):
        netloc = f"{netloc}:{port}"
    path = parsed.path or "/"
    canonical = urlunsplit((parsed.scheme.lower(), netloc, path, parsed.query, ""))
    return Indicator(URL, canonical, value, {"host": host})


def email(value: str, **_) -> Indicator:
    s = _strip(value)
    if s.lower().startswith("mailto:"):
        s = s[7:].split("?", 1)[0]
    s = unquote(s).lower()
    m = _EMAIL.match(s)
    if not m:
        raise InvalidIndicator(f"invalid email: {value}")
    host = _valid_domain(_host(m.group(1)))
    local = s.rsplit("@", 1)[0]
    return Indicator(EMAIL, f"{local}@{host}", value, {"domain": host})


def _e164(s: str, region: str | None) -> str:
    s = s.strip()
    digits = re.sub(r"\D", "", s)
    if s.startswith("00"):
        digits, explicit = digits[2:], True
    else:
        explicit = s.startswith("+")
    if explicit:
        pass
    elif region == "KE" and len(digits) == 12 and digits.startswith("254"):
        pass
    elif region == "KE" and len(digits) == 10 and digits.startswith("0"):
        digits = "254" + digits[1:]
    else:
        # Local numbers without market context are deliberately not guessed.
        raise InvalidIndicator(f"phone number needs +country code or market context: {s}")
    if not 8 <= len(digits) <= 15 or digits.startswith("0"):
        raise InvalidIndicator(f"invalid phone number: {s}")
    if digits.startswith("254") and len(digits) != 12:
        raise InvalidIndicator(f"invalid Kenyan number length: {s}")
    return "+" + digits


def phone(value: str, region: str | None = None, **_) -> Indicator:
    s = _strip(value)
    if s.lower().startswith("tel:"):
        s = s[4:]
    return Indicator(PHONE, _e164(s, region), value)


def whatsapp(value: str, region: str | None = None, **_) -> Indicator:
    s = _strip(value)
    if "://" not in s and not re.match(r"^[\w.-]+\.[a-z]{2,}/", s, re.I):
        return Indicator(WHATSAPP, _e164(s, region), value, {"kind": "number"})
    parsed = urlsplit(s if "://" in s else "https://" + s)
    host = (parsed.hostname or "").lower()
    parts = [p for p in parsed.path.split("/") if p]
    query = parse_qs(parsed.query)
    if host == "chat.whatsapp.com" and parts:
        return Indicator(WHATSAPP, f"group:{parts[0]}", value, {"kind": "group"})
    if host == "wa.me" and len(parts) >= 2 and parts[0] == "message":
        return Indicator(WHATSAPP, f"link:{parts[1]}", value, {"kind": "business_link"})
    number = None
    if host == "wa.me" and parts and parts[0] not in {"qr", "message"}:
        number = parts[0]
    elif host in _WA_HOSTS and query.get("phone"):
        number = query["phone"][0]
    elif parsed.scheme == "whatsapp" and query.get("phone"):
        number = query["phone"][0]
    if not number:
        raise InvalidIndicator(f"WhatsApp link carries no number: {value}")
    # wa.me numbers are international without the plus; never apply a region.
    return Indicator(WHATSAPP, _e164("+" + re.sub(r"\D", "", number), None), value, {"kind": "number"})


def telegram(value: str, **_) -> Indicator:
    s = _strip(value)
    handle = None
    if s.startswith("tg://"):
        handle = (parse_qs(urlsplit(s).query).get("domain") or [""])[0] or None
    elif "://" in s or re.match(r"^(t|telegram)\.(me|dog)/", s, re.I):
        parsed = urlsplit(s if "://" in s else "https://" + s)
        if (parsed.hostname or "").lower() not in _TG_HOSTS:
            raise InvalidIndicator(f"not a Telegram link: {value}")
        parts = [p for p in parsed.path.split("/") if p]
        if parts and parts[0] == "s" and len(parts) > 1:  # public channel preview
            parts = parts[1:]
        if parts and parts[0] == "joinchat" and len(parts) > 1:
            return Indicator(TELEGRAM, f"invite:{parts[1]}", value, {"kind": "invite"})
        if parts and parts[0].startswith("+") and len(parts[0]) > 1:
            return Indicator(TELEGRAM, f"invite:{parts[0][1:]}", value, {"kind": "invite"})
        handle = parts[0] if parts else None
    else:
        handle = s.lstrip("@")
    if not handle or handle.lower() in _TG_RESERVED or not _TG_HANDLE.match(handle):
        raise InvalidIndicator(f"invalid Telegram handle: {value}")
    return Indicator(TELEGRAM, handle.lower(), value, {"kind": "handle"})


def ip(value: str, **_) -> Indicator:
    s = _strip(value).strip("[]").split("%", 1)[0]
    try:
        addr = ipaddress.ip_address(s)
    except ValueError as exc:
        raise InvalidIndicator(f"invalid IP address: {value}") from exc
    mapped = getattr(addr, "ipv4_mapped", None)
    out = mapped if mapped is not None else addr
    return Indicator(IP, str(out), value, {"version": out.version})


def crypto(value: str, **_) -> Indicator:
    s = _strip(value)
    for chain, pattern in _CRYPTO:
        if pattern.match(s):
            # Case-insensitive chains are lowered; base58 is case-sensitive.
            addr = s.lower() if chain == "evm" or s.lower().startswith("bc1") else s
            # No checksum validation: format only, so a typo'd address still dedups
            # with itself but is not proven to be a real wallet.
            return Indicator(CRYPTO, f"{chain}:{addr}", value, {"chain": chain})
    raise InvalidIndicator(f"unrecognised crypto address: {value}")


def payment(value: str, **_) -> Indicator:
    s = _strip(value)
    m = _PAYMENT.match(s)
    if not m:
        raise InvalidIndicator(f"unrecognised payment identifier: {value}")
    kind = "paybill" if "pay" in m.group(1).lower() else "till"
    return Indicator(PAYMENT, f"{kind}:{m.group(2)}", value, {"scheme": kind})


def social(value: str, platform: str | None = None, **_) -> Indicator:
    s = _strip(value)
    if "://" not in s and not re.match(r"^[\w.-]+\.[a-z]{2,}/", s, re.I):
        if not platform:
            raise InvalidIndicator("a bare handle needs a platform hint")
        p = "x" if platform.lower() in {"x", "twitter"} else platform.lower()
        return Indicator(SOCIAL, f"{p}:{s.lstrip('@').rstrip('/').lower()}", value)
    parsed = urlsplit(s if "://" in s else "https://" + s)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise InvalidIndicator(f"only HTTP(S) links are supported: {value}")
    host = (parsed.hostname or "").lower()
    found = _SOCIAL_HOSTS.get(host) or _SOCIAL_HOSTS.get(host[4:] if host.startswith("www.") else host)
    if not found:
        raise InvalidIndicator(f"not a known social platform: {host}")
    p = found
    parts = [x for x in parsed.path.split("/") if x]
    if p == "facebook" and parts and parts[0] == "profile.php":
        pid = (parse_qs(parsed.query).get("id") or [""])[0]
        if not pid.isdigit():
            raise InvalidIndicator(f"Facebook profile link has no id: {value}")
        return Indicator(SOCIAL, f"facebook:id:{pid}", value)
    if p == "linkedin":
        if len(parts) >= 2 and parts[0] in {"in", "company", "school"}:
            return Indicator(SOCIAL, f"linkedin:{parts[0]}/{parts[1].lower()}", value)
        raise InvalidIndicator(f"LinkedIn link is not a profile: {value}")
    if p == "youtube" and len(parts) >= 2 and parts[0] in {"channel", "c", "user"}:
        return Indicator(SOCIAL, f"youtube:{parts[0]}/{parts[1]}", value)
    if not parts or parts[0].lower() in _SOCIAL_RESERVED:
        raise InvalidIndicator(f"social link is not a profile: {value}")
    return Indicator(SOCIAL, f"{p}:{parts[0].lstrip('@').lower()}", value)


# --- dispatch ----------------------------------------------------------------

_BY_HINT = {
    "domain": domain, "url": url, "email": email, "phone": phone, PHONE: phone,
    "whatsapp": whatsapp, "telegram": telegram, "ip": ip, IP: ip, "ip_address": ip,
    "crypto": crypto, CRYPTO: crypto, "payment": payment, PAYMENT: payment,
    "paybill": payment, "till": payment, "social": social, SOCIAL: social,
}


def normalize(value: str, hint: str | None = None, region: str | None = "KE") -> Indicator:
    """Classify and canonicalise `value`.

    A bare URL whose path is "/" and which has no query is the site itself, so it
    becomes a domain: `MPESA-EXAMPLE.COM`, `mpesa-example.com/` and
    `https://mpesa-example.com` are one entity. A URL with a real path stays a URL.
    """
    s = _strip(value)
    if hint:
        h = hint.lower()
        if h in _BY_HINT:
            result = _BY_HINT[h](s, region=region, platform=None)  # type: ignore[operator]   # handlers share **kwargs
        elif h in {"x", "twitter", "facebook", "instagram", "tiktok", "youtube", "linkedin"}:
            result = social(s, platform=h)
        else:
            raise InvalidIndicator(f"unknown indicator hint: {hint}")
        return _collapse_root(result) if result.type == URL else result

    low = s.lower()
    if low.startswith("mailto:"):
        return email(s)
    if low.startswith("tel:"):
        return phone(s, region=region)
    if _PAYMENT.match(s):
        return payment(s)
    if low.startswith(("tg://",)):
        return telegram(s)
    if low.startswith("whatsapp://"):
        return whatsapp(s)
    if s.startswith("@"):
        raise InvalidIndicator("a bare @handle needs a platform hint")
    if "://" in s or "/" in s or "?" in s:
        if "://" in s and urlsplit(s).scheme.lower() not in {"http", "https"}:
            raise InvalidIndicator(f"only HTTP(S) links are supported: {value}")
        host = (urlsplit(s if "://" in s else "//" + s).hostname or "").lower()
        if host.startswith("www."):
            host = host[4:]
        if host in _WA_HOSTS | {"chat.whatsapp.com"}:
            return whatsapp(s)
        if host in _TG_HOSTS:
            return telegram(s)
        if host in _SOCIAL_HOSTS:
            try:
                return social(s)
            except InvalidIndicator:
                pass  # a share/login link is still a URL worth keeping
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        return _collapse_root(url(s))
    if _EMAIL.match(low):
        return email(s)
    try:
        return ip(s)
    except InvalidIndicator:
        pass
    for _, pattern in _CRYPTO:
        if pattern.match(s):
            return crypto(s)
    if re.match(r"^\+?[\d\s\-().]{8,24}$", s) and len(re.sub(r"\D", "", s)) >= 8:
        return phone(s, region=region)
    return domain(s)


def _collapse_root(ind: Indicator) -> Indicator:
    if ind.type != URL:
        return ind
    parsed = urlsplit(ind.canonical)
    if parsed.path == "/" and not parsed.query and not parsed.port:
        try:
            ipaddress.ip_address(ind.meta["host"])
        except ValueError:
            return Indicator(DOMAIN, ind.meta["host"], ind.original)
    return ind


def host_of(ind: Indicator) -> str | None:
    """Hostname an indicator would make the fetcher contact, if any."""
    if ind.type == DOMAIN:
        return ind.canonical
    if ind.type == IP:
        return ind.canonical
    if ind.type == URL:
        return ind.meta.get("host")
    return None


def derived_domain(ind: Indicator) -> Indicator | None:
    """The domain a URL or email belongs to, so pivots can reach the site."""
    if ind.type == URL:
        host = ind.meta.get("host", "")
        try:
            ipaddress.ip_address(host)
            return None
        except ValueError:
            return Indicator(DOMAIN, host, ind.original)
    if ind.type == EMAIL:
        return Indicator(DOMAIN, ind.meta["domain"], ind.original)
    return None


def is_public(ind: Indicator) -> bool:
    """False for anything the hunter must never contact or queue for contact."""
    host = host_of(ind)
    if host is None:
        return True
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return host != "localhost" and not host.endswith(_PRIVATE_SUFFIXES)
    from watchtower.discovery.safe_fetch import is_public_ip       # one definition of "public" for fetching and queueing
    return is_public_ip(host)
