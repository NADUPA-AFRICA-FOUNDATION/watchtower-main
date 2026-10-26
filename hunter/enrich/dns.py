"""DNS enrichment with honest failure semantics.

The older provider swallowed every exception per record type, so NXDOMAIN,
SERVFAIL and a timeout all read as "no records". Here they are different:

  NxDomain     the name does not exist: a real answer.
  NODATA       the name exists but has no record of that type: a real, empty answer.
  DnsFailure   SERVFAIL, timeout, no usable nameserver: we could not look.

`status` is resolved | no_address | nxdomain | error. `complete` is False when
some record types failed, and those failures are kept in `errors`.
"""
from __future__ import annotations

import asyncio
import ipaddress
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

from ..prescore import is_shared_hosting, registrable


class NxDomain(Exception):
    pass


class DnsFailure(Exception):
    pass


Lookup = Callable[[str, str], Awaitable[list]]

LIGHT_TYPES = ("A", "AAAA", "CNAME", "NS")
# The deep pass refreshes addresses too: page capture must act on current answers, not
# the ones from the light pass, which may be hours old.
DEEP_TYPES = ("A", "AAAA", "CNAME", "MX", "TXT")


def system_lookup(timeout: float = 5.0) -> Lookup:
    async def lookup(name: str, rtype: str) -> list[str]:
        import dns.asyncresolver
        import dns.exception
        import dns.resolver
        try:
            answer = await dns.asyncresolver.resolve(name, rtype, lifetime=timeout)
        except dns.resolver.NXDOMAIN as exc:
            raise NxDomain(name) from exc
        except dns.resolver.NoAnswer:
            return []
        except dns.resolver.NoNameservers as exc:
            raise DnsFailure("SERVFAIL: no usable nameserver") from exc
        except dns.exception.Timeout as exc:
            raise DnsFailure("timeout") from exc
        except Exception as exc:
            raise DnsFailure(f"{type(exc).__name__}: {exc}") from exc
        out = set()
        for rr in answer:
            r: Any = rr                              # dnspython's Rdata subclasses differ per record type
            if rtype == "MX":
                out.add(f"{r.preference} {str(r.exchange).rstrip('.').lower()}")
            elif rtype == "TXT":
                out.add(b"".join(r.strings).decode("utf-8", "replace"))
            else:
                out.add(str(r).rstrip(".").lower())
        return sorted(out)
    return lookup


@dataclass
class DnsResult:
    domain: str
    status: str
    records: dict[str, list[str]] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        return not self.errors

    @property
    def ips(self) -> list[str]:
        return sorted({*self.records.get("A", []), *self.records.get("AAAA", [])})

    @property
    def non_public_ips(self) -> list[str]:
        out = []
        for ip in self.ips:
            a = ipaddress.ip_address(ip)
            if a.is_private or a.is_loopback or a.is_link_local or a.is_reserved or a.is_unspecified:
                out.append(ip)
        return out

    def facts(self) -> dict:
        """Deterministic content for evidence: no timestamps, so unchanged answers dedupe."""
        return {"status": self.status, "records": {k: self.records[k] for k in sorted(self.records)},
                "errors": {k: self.errors[k] for k in sorted(self.errors)}}


async def lookup_domain(domain: str, lookup: Lookup, types=LIGHT_TYPES) -> DnsResult:
    res = DnsResult(domain, "error")
    shared = is_shared_hosting(domain)

    async def one(rtype: str, name: str):
        try:
            res.records[rtype] = await lookup(name, rtype)
        except NxDomain:
            raise
        except DnsFailure as exc:
            res.errors[rtype] = str(exc)
        except Exception as exc:  # a custom resolver must not escape as an unclassified crash
            res.errors[rtype] = f"{type(exc).__name__}: {exc}"

    try:
        if "A" in types:
            await one("A", domain)
    except NxDomain:
        res.status = "nxdomain"
        res.notes.append("NXDOMAIN: other record types not queried")
        return res
    rest = []
    for t in types:
        if t == "A":
            continue
        if t == "NS":
            if shared:
                res.notes.append("NS skipped: zone belongs to the hosting platform")
                continue
            rest.append(("NS", registrable(domain)))  # NS lives at the zone apex
        else:
            rest.append((t, domain))
    try:
        await asyncio.gather(*(one(t, n) for t, n in rest))
    except NxDomain:
        res.status = "nxdomain"
        return res

    have_address = bool(res.records.get("A") or res.records.get("AAAA") or res.records.get("CNAME"))
    address_types = [t for t in ("A", "AAAA") if t in types]
    address_answered = all(t in res.records for t in address_types) and bool(address_types)
    if not address_types:
        res.status = "error" if res.errors else "ok"   # a pass that never asked for addresses has none to judge
    elif have_address:
        res.status = "resolved"
    elif address_answered:
        res.status = "no_address"
    else:
        res.status = "error"
    return res
