"""Adapters. Each one has a YAML file beside it holding everything a provider can change
without notice (endpoints, parameters, patterns, pacing), so a repair is a one-line edit."""
from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

import yaml


@lru_cache(maxsize=None)
def load_config(name: str) -> dict:
    return yaml.safe_load((Path(__file__).parent / f"{name}.yaml").read_text())


@dataclass
class Outcome:
    """What one source said. `ok` and `no_results` mean it answered; everything else means it did not."""
    source: str
    status: str                       # ok | no_results | not_found | blocked | rate_limited | error | disabled
    detail: str = ""
    results: list = field(default_factory=list)

    @property
    def answered(self) -> bool:
        return self.status in {"ok", "no_results", "not_found"}
