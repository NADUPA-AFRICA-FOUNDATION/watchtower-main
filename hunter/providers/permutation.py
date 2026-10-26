"""Typo/permutation candidates.

These are generated, not observed: nothing in the world said these names exist.
They carry low confidence and are submitted once per (brand, config) rather than
every run, because re-submitting the same 400 names would inflate
`observation_count` with sightings that never happened.
"""
from __future__ import annotations

import hashlib
import json

from watchtower.discovery.base import SourceHealth

from ..permute import generate
from .base import Discovered, DiscoveryResult, HuntProvider, _now


class PermutationProvider(HuntProvider):
    name = "permutation"

    def __init__(self, force: bool = False):
        self.force = force

    def capabilities(self):
        return ("domain_generation",)

    @staticmethod
    def fingerprint(brand, cfg) -> str:
        blob = json.dumps([brand.__dict__, cfg.permutations.__dict__, cfg.prescore.weights,
                           cfg.prescore.keywords], sort_keys=True, default=str)
        return hashlib.sha256(blob.encode()).hexdigest()[:16]

    async def discover(self, brand, cfg, cursors):
        health = SourceHealth(self.name, "operational", self.capabilities(), last_attempt=_now())
        key = f"{self.name}:{brand.name}:fingerprint"
        fp = self.fingerprint(brand, cfg)
        if not self.force and cursors.get(key) == fp:
            health.results, health.last_success = 0, _now()
            health.detail = "unchanged since last run; nothing new to generate"
            return DiscoveryResult([], health)
        perms = generate(brand, cfg)
        health.results, health.last_success = len(perms), _now()
        health.detail = f"{len(perms)} candidates generated"
        return DiscoveryResult(
            [Discovered(p.domain, "domain", self.name, query=p.kind, confidence=0.2,
                        metadata={"permutation_kind": p.kind, "label": p.label})
             for p in perms],
            health, {key: fp},
        )
