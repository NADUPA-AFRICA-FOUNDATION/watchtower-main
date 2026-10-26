"""Discovery provider contract for the hunter.

Reuses SourceHealth from watchtower.discovery so the coverage table speaks one
status vocabulary. Providers report their own failures in `health`; the runner
also guards against a provider that raises anyway (see hunter.ingest).

A provider never advances its own cursor. It returns `cursor_updates`, and the
runner applies them only after the candidates were stored, so a crash between
the two cannot lose certificates.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from watchtower.discovery.base import SourceHealth


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Discovered:
    indicator: str
    indicator_type: str | None          # hint for normalize(); None = auto-detect
    source: str
    query: str | None = None
    confidence: float = 0.5
    metadata: dict[str, Any] = field(default_factory=dict)
    discovered_at: str = field(default_factory=_now)
    priority: float | None = None       # None = use the pre-score


@dataclass
class DiscoveryResult:
    candidates: list[Discovered]
    health: SourceHealth
    cursor_updates: dict[str, str] = field(default_factory=dict)
    noise_filtered: int = 0             # returned by the source but not brand-related
    malformed: int = 0                  # returned but unparseable as an indicator
    notes: list[str] = field(default_factory=list)


class HuntProvider:
    name = "provider"
    credentials_required = False

    def capabilities(self) -> tuple[str, ...]:
        return ()

    async def discover(self, brand, cfg, cursors: dict[str, str]) -> DiscoveryResult:
        raise NotImplementedError

    async def healthcheck(self) -> SourceHealth:
        return SourceHealth(self.name, "configured", self.capabilities(), self.credentials_required,
                            detail="Availability is verified by each run")

    def rate_limit_status(self) -> dict[str, Any]:
        return {}

    async def close(self) -> None:
        return None
