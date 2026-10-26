"""Live TLS certificate capture, pinned to a validated public address.

The older provider called socket.create_connection(domain, 443), which resolves
inside the connect: a candidate that resolves to 127.0.0.1 or a cloud metadata
address would be probed. Here the name is resolved once through
watchtower.discovery.safe_fetch.resolve_public (which rejects non-public sets),
and the handshake goes to that address with the candidate as SNI.

Hostile sites often have invalid certificates and that is still evidence, so a
failed verification is retried unverified purely to read the certificate, and the
verification error is recorded. No request is sent over the connection.

status: ok | unreachable | tls_error | unresolved | blocked
"""
from __future__ import annotations

import asyncio
import hashlib
import ssl
from dataclasses import dataclass, field
from datetime import timezone

from watchtower.discovery.safe_fetch import UnsafeTarget, resolve_public


@dataclass
class TlsResult:
    domain: str
    status: str
    ip: str | None = None
    fingerprint: str | None = None
    subject_cn: str | None = None
    issuer: str | None = None
    sans: list[str] = field(default_factory=list)
    not_before: str | None = None
    not_after: str | None = None
    verified: bool | None = None
    verification_error: str | None = None
    error: str | None = None

    def facts(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if k != "error" or v}


def parse_certificate(der: bytes) -> dict:
    from cryptography import x509
    from cryptography.x509.oid import ExtensionOID, NameOID
    cert = x509.load_der_x509_certificate(der)

    def attr(name, oid):
        got = name.get_attributes_for_oid(oid)
        return got[0].value if got else None
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        sans = san.get_values_for_type(x509.DNSName)  # type: ignore[attr-defined]
    except x509.ExtensionNotFound:
        sans = []
    nb = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before.replace(tzinfo=timezone.utc)
    na = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=timezone.utc)
    return {
        "fingerprint": hashlib.sha256(der).hexdigest(),
        "subject_cn": attr(cert.subject, NameOID.COMMON_NAME),
        "issuer": " / ".join(x for x in (attr(cert.issuer, NameOID.ORGANIZATION_NAME),
                                         attr(cert.issuer, NameOID.COMMON_NAME)) if x) or None,
        "sans": sorted({s.lower() for s in sans})[:100],
        "not_before": nb.isoformat(), "not_after": na.isoformat(),
    }


async def _handshake(ip: str, host: str, port: int, verify: bool, timeout: float) -> bytes:
    if verify:
        ctx = ssl.create_default_context()
    else:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    _, writer = await asyncio.wait_for(
        asyncio.open_connection(ip, port, ssl=ctx, server_hostname=host), timeout)
    try:
        return writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
    finally:
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), 2)
        except Exception:
            pass


class TlsEnricher:
    def __init__(self, timeout: float = 7.0, port: int = 443, resolver=resolve_public, handshake=_handshake):
        self.timeout, self.port = timeout, port
        self._resolve, self._handshake = resolver, handshake

    async def fetch(self, domain: str) -> TlsResult:
        try:
            addresses = await self._resolve(domain)
        except UnsafeTarget as exc:
            status = "unresolved" if str(exc).startswith("DNS resolution failed") else "blocked"
            return TlsResult(domain, status, error=str(exc))
        res = TlsResult(domain, "unreachable")
        for ip in addresses[:2]:
            res.ip = ip
            verify_error = None
            try:
                try:
                    der = await self._handshake(ip, domain, self.port, True, self.timeout)
                    res.verified = True
                except ssl.SSLCertVerificationError as exc:
                    verify_error = exc.verify_message or str(exc)
                    der = await self._handshake(ip, domain, self.port, False, self.timeout)
                    res.verified = False
            except (ssl.SSLError, ValueError) as exc:
                res.status, res.error = "tls_error", f"{type(exc).__name__}: {exc}"[:300]
                continue
            except (OSError, asyncio.TimeoutError) as exc:
                res.status, res.error = "unreachable", f"{type(exc).__name__}: {exc}"[:300]
                continue
            if not der:
                res.status, res.error = "tls_error", "no certificate presented"
                continue
            try:
                for k, v in parse_certificate(der).items():
                    setattr(res, k, v)
            except Exception as exc:
                res.status, res.error = "tls_error", f"unparseable certificate: {type(exc).__name__}"
                continue
            res.status, res.error, res.verification_error = "ok", None, verify_error
            return res
        return res
