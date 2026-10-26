"""Read-side graph queries: the analyst's questions, answered from stored evidence.

  What other domains use this phone number?       domains_using("whatsapp", "+254...")
  What infrastructure shares this IP?             domains_using("ip_address", "...")
  Which campaigns use this payment identifier?    campaigns_for_indicator("payment_identifier", "paybill:123456")
  Where was this indicator first discovered?      first_discovered(id)
  What led Mnara to investigate this domain?      what_led_to(id)

Everything returned carries ids back into the evidence table. Nothing here writes.
"""
from __future__ import annotations

import json
from typing import Any

_PHONE = ("phone_number", "whatsapp")
GROUPS = {"domain": "Domains", "url": "URLs", "ip_address": "IPs", "phone_number": "Phone numbers", "whatsapp": "WhatsApp",
          "telegram": "Telegram", "email": "Emails", "payment_identifier": "Payment identifiers",
          "crypto_wallet": "Crypto wallets", "certificate": "Certificates", "nameserver": "Nameservers",
          "social_account": "Social profiles", "analytics_id": "Analytics IDs", "html_fingerprint": "Page templates",
          "registrar": "Registrars"}
THEMES = (("Investment", {"guaranteed_returns", "fee_language", "crypto_wallet"}),
          ("Credential phishing", {"login_form", "pin_field", "otp_field", "card_field"}),
          ("Payment fraud", {"payment_instruction", "external_payment_domain"}))


class GraphQueries:
    def __init__(self, store, graph):
        self.store, self.graph = store, graph
        self.conn = graph.conn

    def _node_ids(self, node_type: str, canonical: str) -> list[str]:
        types = _PHONE if node_type in _PHONE else (node_type,)
        q = ",".join("?" * len(types))
        return [r["id"] for r in self.conn.execute(
            f"SELECT id FROM entities WHERE canonical_value=? AND entity_type IN ({q})", (canonical, *types))]

    def _cand(self, entity_id: str) -> dict:
        c = self.store.get(entity_id) or {}
        return {"status": c.get("status"), "risk_score": c.get("risk_score"), "classification": c.get("classification"),
                "market": c.get("market"), "campaign_id": c.get("campaign_id")}

    # -- the analyst's questions ----------------------------------------------------------------------------
    def domains_using(self, node_type: str, canonical: str) -> list[dict[str, Any]]:
        ids = self._node_ids(node_type, canonical)
        if not ids:
            return []
        q = ",".join("?" * len(ids))
        rows = self.conn.execute(
            f"""SELECT d.id, d.canonical_value AS domain, r.relationship_type AS relationship, r.evidence_id, r.confidence,
                       ev.source_url, ev.observed_at
                FROM relationships r JOIN entities d ON d.id=r.source_entity_id JOIN evidence ev ON ev.id=r.evidence_id
                WHERE r.target_entity_id IN ({q}) AND d.entity_type='domain'
                  AND r.relationship_type NOT LIKE 'shares\\_%' ESCAPE '\\' AND r.relationship_type!='member_of_campaign'
                ORDER BY ev.observed_at, d.canonical_value""", ids).fetchall()
        return [{**dict(r), **self._cand(r["id"])} for r in rows]

    def campaigns_for_indicator(self, node_type: str, canonical: str) -> list[dict[str, Any]]:
        doms = {d["id"] for d in self.domains_using(node_type, canonical)}
        if not doms:
            return []
        q = ",".join("?" * len(doms))
        return [dict(r) for r in self.conn.execute(
            f"""SELECT c.id, c.public_id, c.brand, c.correlation_score, c.correlation_label, c.system_classification, c.status,
                       COUNT(DISTINCT ce.entity_id) AS members_using
                FROM campaigns c JOIN campaign_entities ce ON ce.campaign_id=c.id
                WHERE ce.entity_id IN ({q}) AND c.status!='merged' GROUP BY c.id ORDER BY c.created_at""", tuple(doms))]

    def first_discovered(self, cid: str) -> dict[str, Any] | None:
        cand = self.store.get(cid)
        if not cand:
            return None
        obs = self.store.observations(cid)[0] if self.store.observations(cid) else None
        return {"source": cand["discovery_source"], "at": cand["first_seen"], "query": obs["query"] if obs else None,
                "parent_id": cand["parent_id"], "depth": cand["depth"], "sightings": cand["observation_count"],
                "sources_seen": cand["sources_seen"]}

    def what_led_to(self, cid: str) -> list[dict[str, Any]]:
        return self.store.lineage(cid)

    # -- views ------------------------------------------------------------------------------------------------
    def indicators_of(self, cid: str) -> dict[str, list[dict]]:
        out: dict[str, list[dict]] = {}
        for r in self.conn.execute(
                """SELECT e.id, e.entity_type AS type, e.canonical_value AS value, r.relationship_type AS relationship,
                          r.evidence_id, r.confidence
                   FROM relationships r JOIN entities e ON e.id=r.target_entity_id
                   WHERE r.source_entity_id=? AND r.relationship_type NOT LIKE 'shares\\_%' ESCAPE '\\'
                     AND r.relationship_type!='member_of_campaign' AND e.entity_type!='campaign'
                   ORDER BY e.entity_type, e.canonical_value""", (cid,)):
            out.setdefault(GROUPS.get(r["type"], r["type"]), []).append(dict(r))
        return out

    def entity_view(self, entity_id: str) -> dict[str, Any] | None:
        ent = self.conn.execute("SELECT * FROM entities WHERE id=?", (entity_id,)).fetchone()
        if not ent:
            return None
        rels = lambda col: [dict(r) for r in self.conn.execute(      # noqa: E731
            f"""SELECT r.*, o.entity_type AS other_type, o.canonical_value AS other_value FROM relationships r
                JOIN entities o ON o.id=r.{'target' if col == 'source' else 'source'}_entity_id
                WHERE r.{col}_entity_id=? ORDER BY r.relationship_type, o.canonical_value""", (entity_id,))]
        return {"entity": {**dict(ent), "metadata": json.loads(ent["metadata"] or "{}")},
                "evidence": [dict(r) for r in self.conn.execute("SELECT * FROM evidence WHERE entity_id=? ORDER BY observed_at, rowid", (entity_id,))],
                "outgoing": rels("source"), "incoming": rels("target"),
                "candidate": self.store.get(entity_id), "scores": self.store.score_history(entity_id),
                "lineage": self.store.lineage(entity_id) if self.store.get(entity_id) else []}

    def _theme(self, member_ids: list[str]) -> str:
        sigs = []
        for m in member_ids:
            row = self.store.latest_score(m)
            sigs.append({r["signal"] for r in (row["reasons"] if row else []) if r["weight"] > 0})
        for name, wanted in THEMES:
            if sum(1 for s in sigs if s & wanted) * 2 >= len(sigs):
                return name
        return "Impersonation"

    def campaign(self, campaign_id: str) -> dict[str, Any] | None:
        row = self.conn.execute("SELECT * FROM campaigns WHERE id=? OR public_id=?", (campaign_id, campaign_id)).fetchone()
        if not row:
            return None
        camp = dict(row)
        ids = [r["entity_id"] for r in self.conn.execute("SELECT entity_id FROM campaign_entities WHERE campaign_id=?", (camp["id"],))]
        members = []
        for m in ids:
            e = self.conn.execute("SELECT canonical_value FROM entities WHERE id=?", (m,)).fetchone()
            members.append({"id": m, "domain": e["canonical_value"] if e else m, **self._cand(m)})
        q = ",".join("?" * len(ids)) or "''"
        infra = {GROUPS.get(r["t"], r["t"]): r["n"] for r in self.conn.execute(
            f"""SELECT e.entity_type AS t, COUNT(DISTINCT e.canonical_value) AS n FROM relationships r
                JOIN entities e ON e.id=r.target_entity_id WHERE r.source_entity_id IN ({q})
                  AND r.relationship_type NOT LIKE 'shares\\_%' ESCAPE '\\' AND r.relationship_type!='member_of_campaign'
                  AND e.entity_type NOT IN ('campaign','domain','registrar','html_fingerprint') GROUP BY e.entity_type""", ids)}
        infra["Domains"] = len(ids)
        why = []
        for r in self.conn.execute(
                f"""SELECT DISTINCT ev.observed_value, ev.id FROM relationships r JOIN evidence ev ON ev.id=r.evidence_id
                    WHERE r.relationship_type LIKE 'shares\\_%' ESCAPE '\\' AND r.source_entity_id IN ({q}) ORDER BY ev.observed_at""", ids):
            try:
                why.append({**json.loads(r["observed_value"]), "evidence_id": r["id"]})
            except ValueError:
                continue
        last = [self.store.get(m) for m in ids]
        n = camp["public_id"].rsplit("-", 1)[-1].lstrip("0") or "0"
        theme = self._theme(ids)
        return {**camp, "name": f"{camp['brand']} {theme} Cluster #{n}", "theme": theme, "members": members,
                "infrastructure": dict(sorted(infra.items())), "why_related": why,
                "first_seen": camp["created_at"], "last_active": max((c["last_seen"] for c in last if c), default=camp["updated_at"]),
                "events": self.store.campaign_events(camp["id"])}

    def campaigns(self, limit: int = 100) -> list[dict[str, Any]]:
        rows = self.conn.execute("SELECT id FROM campaigns WHERE status!='merged' ORDER BY updated_at DESC LIMIT ?", (limit,)).fetchall()
        return [c for c in (self.campaign(r["id"]) for r in rows) if c]

    def subgraph(self, campaign_id: str) -> dict[str, Any]:
        """Nodes and edges for a graph view: members, the infrastructure they use, derived links, provenance on every edge."""
        camp = self.conn.execute("SELECT id FROM campaigns WHERE id=? OR public_id=?", (campaign_id, campaign_id)).fetchone()
        if not camp:
            return {"nodes": [], "edges": []}
        ids = [r["entity_id"] for r in self.conn.execute("SELECT entity_id FROM campaign_entities WHERE campaign_id=?", (camp["id"],))]
        q = ",".join("?" * len(ids)) or "''"
        edges = [dict(r) for r in self.conn.execute(
            f"""SELECT r.id, r.source_entity_id AS source, r.target_entity_id AS target, r.relationship_type AS type,
                       r.confidence, r.evidence_id FROM relationships r
                WHERE r.source_entity_id IN ({q}) AND r.relationship_type!='member_of_campaign'""", ids)]
        node_ids = set(ids) | {e["target"] for e in edges}
        nodes = []
        for nid in sorted(node_ids):
            e = self.conn.execute("SELECT id, entity_type, canonical_value FROM entities WHERE id=?", (nid,)).fetchone()
            if e:
                nodes.append({"id": e["id"], "type": e["entity_type"], "label": e["canonical_value"], "member": e["id"] in ids,
                              **({"risk_score": self.store.get(nid)["risk_score"]} if nid in ids and self.store.get(nid) else {})})
        return {"nodes": nodes, "edges": edges}
