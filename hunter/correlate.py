"""Relationship correlation and campaign clustering.

Domains are linked when they share a node in the graph. Not all sharing is equal:

  strong  same phone/WhatsApp number, Telegram handle, payment identifier, crypto wallet,
          analytics id, email address, form-submission endpoint, or distinctive page template
  medium  same IP, nameserver, certificate, redirect/CNAME target, social profile
  weak    same registrar, a link to the same site, mass-market DNS or a CDN address

A pair of domains joins a campaign through one strong link, or `medium_links_needed` independent
medium links. Weak links are kept as supporting detail and can never merge anything, so sharing
Cloudflare, AWS or a registrar is not a campaign. A node used by many domains counts for less
(`uncommon_max_domains`) and past `generic_node_max_domains` not at all.

Every derived edge references a `correlation` evidence row that names the shared node and the
sightings it rests on; nothing is inferred without a citation. Campaigns only grow or merge here:
splitting one is an analyst decision. Every change is appended to `hunt_campaign_events`.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field

from investigation.models import Entity, Evidence, Relationship, now as iso_now

from .search import is_common_infra_ip

NODE_TYPES = ("phone_number", "whatsapp", "telegram", "payment_identifier", "crypto_wallet", "analytics_id",
              "html_fingerprint", "email", "social_account", "ip_address", "nameserver", "certificate",
              "registrar", "domain")
_PHONE = {"phone_number", "whatsapp"}
_DERIVED = ("shares_", "member_of_campaign")


@dataclass
class Link:
    name: str                 # shares_phone, shares_ip, ...
    strength: str             # strong | medium | weak
    node_type: str
    node_value: str
    weight: float
    users: int                # how many domains use this node
    a: str
    b: str
    evidence_ids: list = field(default_factory=list)

    def dict(self) -> dict:
        return {"link": self.name, "strength": self.strength, "node": f"{self.node_type}:{self.node_value}",
                "weight": round(self.weight, 3), "users": self.users, "evidence_ids": self.evidence_ids}


@dataclass
class Cluster:
    members: list                                  # domain entity ids, sorted
    names: dict                                    # id -> canonical domain
    pairs: dict                                    # (a, b) -> list[Link]
    confidence: float
    nodes: dict = field(default_factory=dict)      # "type:value" -> {"strength", "domains": [...]}

    def why(self) -> list[dict]:
        out = []
        for key, info in sorted(self.nodes.items()):
            out.append({"node": key, **info})
        return out


def _noisy_or(weights: list[float]) -> float:
    p = 1.0
    for w in weights:
        p *= 1 - w
    return 1 - p


class Correlator:
    def __init__(self, store, graph, cfg):
        self.store, self.graph, self.cfg = store, graph, cfg
        self.cc = cfg.correlation

    # -- classification --------------------------------------------------------------------------------
    def classify(self, node_type: str, value: str, rel_type: str, where: list) -> tuple[str, str] | None:
        if node_type in _PHONE:
            return "shares_phone", "strong"
        simple = {"telegram": ("shares_telegram", "strong"), "payment_identifier": ("shares_payment_identifier", "strong"),
                  "crypto_wallet": ("shares_crypto_wallet", "strong"), "analytics_id": ("shares_analytics_id", "strong"),
                  "html_fingerprint": ("shares_html_fingerprint", "strong"), "email": ("shares_email", "strong"),
                  "social_account": ("shares_social_account", "medium"), "certificate": ("shares_certificate", "medium"),
                  "registrar": ("shares_registrar", "weak")}
        if node_type in simple:
            return simple[node_type]
        if node_type == "ip_address":
            return ("shares_ip", "weak") if is_common_infra_ip(value) else ("shares_ip", "medium")
        if node_type == "nameserver":
            common = any(m in value for m in self.cc.common_nameserver_markers)
            return ("shares_nameserver", "weak" if common else "medium")
        if node_type == "domain":
            if "form_action" in where:
                return "shares_form_endpoint", "strong"      # two sites posting credentials to one collector
            if rel_type in {"redirects_to", "cname_to"} or {"js_redirect", "meta_refresh"} & set(where):
                return "shares_redirect_target", "medium"
            return "shares_link_target", "weak"
        return None

    def _weight(self, strength: str, users: int) -> float:
        base = {"strong": self.cc.strong_weight, "medium": self.cc.medium_weight, "weak": self.cc.weak_weight}[strength]
        if users > self.cc.uncommon_max_domains:
            base *= self.cc.uncommon_max_domains / users            # the more common, the less it proves
        return base

    # -- reading the graph ------------------------------------------------------------------------------
    def _where(self, evidence_id: str) -> list:
        row = self.graph.conn.execute("SELECT raw_metadata FROM evidence WHERE id=?", (evidence_id,)).fetchone()
        try:
            w = json.loads(row["raw_metadata"] or "{}").get("where", []) if row else []
        except ValueError:
            return []
        return w if isinstance(w, list) else [w]

    def _participants(self, node_ids: list[str]) -> list[dict]:
        q = ",".join("?" * len(node_ids))
        return [dict(r) for r in self.graph.conn.execute(
            f"""SELECT r.source_entity_id AS d, r.evidence_id AS ev, r.relationship_type AS rt, r.target_entity_id AS n
                FROM relationships r JOIN entities s ON s.id=r.source_entity_id
                WHERE s.entity_type='domain' AND r.target_entity_id IN ({q})
                  AND r.relationship_type NOT LIKE 'shares\\_%' ESCAPE '\\' AND r.relationship_type!='member_of_campaign'""", node_ids)]

    def _outgoing(self, domain_ids: list[str]) -> list[dict]:
        q, t = ",".join("?" * len(domain_ids)), ",".join("?" * len(NODE_TYPES))
        return [dict(r) for r in self.graph.conn.execute(
            f"""SELECT r.source_entity_id AS d, r.target_entity_id AS n, r.relationship_type AS rt, r.evidence_id AS ev,
                       e.entity_type AS nt, e.canonical_value AS nv
                FROM relationships r JOIN entities e ON e.id=r.target_entity_id
                WHERE r.source_entity_id IN ({q}) AND e.entity_type IN ({t})
                  AND r.relationship_type NOT LIKE 'shares\\_%' ESCAPE '\\' AND r.relationship_type!='member_of_campaign'""",
            (*domain_ids, *NODE_TYPES))]

    def _identity_nodes(self, nt: str, nv: str) -> list[str]:
        """A number is one identity whether it was seen as a phone or a WhatsApp contact."""
        types = tuple(_PHONE) if nt in _PHONE else (nt,)
        q = ",".join("?" * len(types))
        return [r["id"] for r in self.graph.conn.execute(
            f"SELECT id FROM entities WHERE canonical_value=? AND entity_type IN ({q})", (nv, *types))]

    def component(self, domain_id: str) -> tuple[set, dict]:
        """Domains reachable through shared nodes, and for each node its participants."""
        seen, frontier = {domain_id}, {domain_id}
        nodes: dict = {}
        for _ in range(8):
            if not frontier or len(seen) > self.cc.max_cluster_size:
                break
            new = set()
            for row in self._outgoing(sorted(frontier)):
                key = (row["nt"] if row["nt"] not in _PHONE else "phone", row["nv"])
                info = nodes.setdefault(key, {"type": row["nt"], "value": row["nv"], "parts": {}})
                info["parts"].setdefault(row["d"], []).append((row["ev"], row["rt"]))
                if row["nt"] == "domain":                       # the node is itself a domain that may be investigated
                    info["parts"].setdefault(row["n"], []).append((row["ev"], "self"))
                    new.add(row["n"])                           # so it can be a member, and its own links are followed
            for key, info in nodes.items():
                if info.get("expanded"):
                    continue
                info["expanded"] = True
                ids = self._identity_nodes(info["type"], info["value"])
                for p in self._participants(ids):
                    info["parts"].setdefault(p["d"], []).append((p["ev"], p["rt"]))
                    new.add(p["d"])
            frontier = {d for d in new if d not in seen}
            seen |= frontier
        return seen, nodes

    # -- clustering ---------------------------------------------------------------------------------------------
    def clusters_for(self, domain_id: str) -> list[Cluster]:
        domains, nodes = self.component(domain_id)
        members = {d for d in domains if self.store.get(d) is not None}      # investigated candidates only
        links: dict[tuple, list[Link]] = {}
        node_info: dict[str, dict] = {}
        for (_, _), info in nodes.items():
            parts = info["parts"]
            users = {d for d in parts if d in members}
            if len(users) < 2 or len(parts) > self.cc.generic_node_max_domains:
                continue                                                      # nothing shared, or used everywhere
            # Describe the link from a real sighting, not from the node's own "self" participation.
            first = next(((ev, rt) for d in sorted(users) for ev, rt in parts[d] if rt != "self"), next(iter(parts[sorted(users)[0]])))
            where = self._where(first[0]) if info["type"] == "domain" else []
            rel = first[1]
            cls = self.classify(info["type"], info["value"], rel, where)
            if cls is None:
                continue
            name, strength = cls
            w = self._weight(strength, len(parts))
            key = f"{info['type']}:{info['value']}"
            node_info[key] = {"strength": strength, "link": name, "domains": sorted(users), "users": len(parts)}
            for a in sorted(users):
                for b in sorted(users):
                    if a < b:
                        ev = [e for d in (a, b) for e, _ in parts[d]][:4]
                        links.setdefault((a, b), []).append(Link(name, strength, info["type"], info["value"], w, len(parts), a, b, ev))
        # which pairs qualify
        parent = {m: m for m in members}

        def find(x):
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x
        qualifying: dict[tuple, float] = {}
        for pair, ls in links.items():
            strong = [l for l in ls if l.strength == "strong" and l.weight >= self.cc.medium_weight]
            medium = {(l.node_type, l.node_value) for l in ls if l.strength == "medium"}
            if not strong and len(medium) < self.cc.medium_links_needed:
                continue
            conf = _noisy_or([l.weight for l in ls])
            if conf >= self.cc.min_pair_confidence:
                qualifying[pair] = conf
                parent[find(pair[0])] = find(pair[1])
        groups: dict[str, list] = {}
        for m in members:
            groups.setdefault(find(m), []).append(m)
        out = []
        for g in groups.values():
            if len(g) < 2:
                continue
            g = sorted(g)
            gp = {p: links[p] for p in qualifying if p[0] in g and p[1] in g}
            best = {m: max((c for p, c in qualifying.items() if m in p), default=0.0) for m in g}
            conf = round(min(0.99, sum(best.values()) / len(g)), 3)
            names = {m: self.store.get(m)["canonical"] for m in g}
            cn = {k: v for k, v in node_info.items() if len(set(v["domains"]) & set(g)) >= 2}
            out.append(Cluster(g, names, gp, conf, cn))
        return out

    # -- persistence --------------------------------------------------------------------------------------------------
    def _campaign_rows(self, member_ids: list[str]) -> list[dict]:
        q = ",".join("?" * len(member_ids))
        return [dict(r) for r in self.graph.conn.execute(
            f"""SELECT DISTINCT c.* FROM campaigns c JOIN campaign_entities ce ON ce.campaign_id=c.id
                WHERE ce.entity_id IN ({q}) AND c.status!='merged' ORDER BY c.created_at, c.id""", member_ids)]

    def _next_public_id(self) -> str:
        year = iso_now()[:4]
        n = self.graph.conn.execute("SELECT COUNT(*) FROM campaigns WHERE public_id LIKE ?", (f"WT-CMP-{year}-%",)).fetchone()[0] + 1
        return f"WT-CMP-{year}-{n:04d}"

    def persist(self, cluster: Cluster, brand: str, iid: str, trigger: str = "correlation") -> dict:
        """Create, extend or merge the campaign this cluster belongs to. Returns what changed."""
        conn, members = self.graph.conn, cluster.members
        existing = self._campaign_rows(members)
        scores = [(self.store.latest_score(m) or {}) for m in members]
        top = max(scores, key=lambda r: r.get("score", -1), default={})
        threat, klass = top.get("score"), top.get("classification", "UNASSESSED")
        label = "Very High" if cluster.confidence >= 0.8 else "High" if cluster.confidence >= 0.6 else "Moderate"
        merged_from, added, created = [], list(members), False
        with conn:
            if not existing:
                cid, public, created = str(uuid.uuid4()), self._next_public_id(), True
                conn.execute("INSERT INTO campaigns VALUES(?,?,?,?,?,?,?,?,?,?)",
                             (cid, public, brand, round(cluster.confidence * 100), label, threat, klass, "active", iso_now(), iso_now()))
            else:
                keep = existing[0]
                cid, public = keep["id"], keep["public_id"]
                prior = {r["entity_id"] for r in conn.execute("SELECT entity_id FROM campaign_entities WHERE campaign_id=?", (cid,))}
                for other in existing[1:]:                           # merge: the oldest campaign survives
                    merged_from.append(other["public_id"])
                    conn.execute("UPDATE campaign_entities SET campaign_id=? WHERE campaign_id=? AND entity_id NOT IN "
                                 "(SELECT entity_id FROM campaign_entities WHERE campaign_id=?)", (cid, other["id"], cid))
                    conn.execute("DELETE FROM campaign_entities WHERE campaign_id=?", (other["id"],))
                    conn.execute("UPDATE campaigns SET status='merged', updated_at=? WHERE id=?", (iso_now(), other["id"]))
                    prior |= {r["entity_id"] for r in conn.execute("SELECT entity_id FROM campaign_entities WHERE campaign_id=?", (cid,))}
                added = [m for m in members if m not in prior]
                conn.execute("UPDATE campaigns SET correlation_score=?, correlation_label=?, threat_score=?, system_classification=?, "
                             "updated_at=? WHERE id=?",
                             (round(cluster.confidence * 100), label, threat, klass, iso_now(), cid))
            for m in members:
                conn.execute("INSERT OR REPLACE INTO campaign_entities VALUES(?,?,?)", (cid, m, cluster.confidence))
        # evidence + derived relationships (each cites the sightings it rests on)
        camp = Entity("campaign", public, public, metadata={"campaign_id": cid})
        for m in members:
            ev = Evidence(iid, m, "correlation", "campaign_membership",
                          json.dumps({"campaign": public, "confidence": cluster.confidence, "shared": cluster.why(), "members": sorted(cluster.names.values())},
                                     sort_keys=True), None, {"campaign": public}, cluster.confidence)
            rel = [Relationship(iid, m, camp.id, "member_of_campaign", cluster.confidence, ev.id)]
            self.graph.persist(iid, [Entity("domain", cluster.names[m], cluster.names[m]), camp], [ev], rel)
        for (a, b), ls in sorted(cluster.pairs.items()):
            by_name: dict[str, list[Link]] = {}
            for l in ls:
                by_name.setdefault(l.name, []).append(l)
            for name, group in by_name.items():
                ev = Evidence(iid, a, "correlation", "correlation",
                              json.dumps({"link": name, "between": [cluster.names[a], cluster.names[b]],
                                          "nodes": sorted({f"{l.node_type}:{l.node_value}" for l in group}),
                                          "strength": group[0].strength, "based_on": sorted({e for l in group for e in l.evidence_ids})},
                                         sort_keys=True), None, {"campaign": public}, round(_noisy_or([l.weight for l in group]), 3))
                self.graph.persist(iid, [], [ev], [Relationship(iid, a, b, name, ev.confidence, ev.id)])
        for m in members:
            self.store.set_campaign(m, cid)
        if created:
            self.store.log_campaign_event(cid, "created", {"public_id": public, "members": sorted(cluster.names.values()),
                                                           "confidence": cluster.confidence, "trigger": trigger})
        elif added or merged_from:
            self.store.log_campaign_event(cid, "merged" if merged_from else "expanded",
                                          {"public_id": public, "added": sorted(cluster.names[m] for m in added if m in cluster.names),
                                           "merged_from": merged_from, "members": len(members), "confidence": cluster.confidence,
                                           "trigger": trigger})
        return {"campaign_id": cid, "public_id": public, "created": created, "added": added, "merged_from": merged_from,
                "members": members, "confidence": cluster.confidence, "new_members": len(added)}

    def update_for(self, domain_id: str, brand: str, iid: str, trigger: str = "deep_pass") -> list[dict]:
        return [self.persist(c, brand, iid, trigger) for c in self.clusters_for(domain_id) if domain_id in c.members]

    def rebuild(self, brand: str, iid: str) -> list[dict]:
        done, out = set(), []
        for cand in self.store.list(limit=1_000_000):
            if cand["indicator_type"] != "domain" or cand["id"] in done:
                continue
            for c in self.clusters_for(cand["id"]):
                done |= set(c.members)
                out.append(self.persist(c, brand, iid, "rebuild"))
        return out
