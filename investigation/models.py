from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

EntityType = Literal[
    "brand",
    "domain",
    "url",
    "social_account",
    "social_post",
    "phone_number",
    "email",
    "ip_address",
    "certificate",
    "registrar",
    "nameserver",
    "dns_record",
    "asn",
    "payment_identifier",
    "favicon",
    "analytics_id",
    "html_fingerprint",
    "hosting_provider",
    "company",
    "app",
    "whatsapp",
    "telegram",
    "crypto_wallet",
    "campaign",
]


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def stable_id(kind: str, value: str) -> str:
    return f"{kind}:{hashlib.sha256(value.encode()).hexdigest()[:24]}"


@dataclass
class Entity:
    entity_type: EntityType
    canonical_value: str
    display_value: str
    platform: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0
    first_seen: str = field(default_factory=now)
    last_seen: str = field(default_factory=now)
    id: str = ""

    def __post_init__(self):
        self.id = self.id or stable_id(self.entity_type, self.canonical_value)

    def dict(self):
        return asdict(self)


@dataclass
class Evidence:
    investigation_id: str
    entity_id: str
    source: str
    evidence_type: str
    observed_value: str
    source_url: str | None = None
    raw_metadata: dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0
    observed_at: str = field(default_factory=now)
    id: str = ""

    def __post_init__(self):
        basis = f"{self.investigation_id}|{self.entity_id}|{self.source}|{self.evidence_type}|{self.observed_value}|{self.source_url}"
        self.id = self.id or stable_id("evidence", basis)


@dataclass
class Relationship:
    investigation_id: str
    source_entity_id: str
    target_entity_id: str
    relationship_type: str
    confidence: float
    evidence_id: str
    first_seen: str = field(default_factory=now)
    last_seen: str = field(default_factory=now)
    id: str = ""

    def __post_init__(self):
        if not self.evidence_id:
            raise ValueError("relationships require evidence")
        basis = f"{self.investigation_id}|{self.source_entity_id}|{self.target_entity_id}|{self.relationship_type}|{self.evidence_id}"
        self.id = self.id or stable_id("relationship", basis)
