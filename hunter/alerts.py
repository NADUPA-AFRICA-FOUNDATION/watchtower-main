"""Alerting without notification fatigue.

An alert is raised only for:
  new_high_priority        a candidate reaches HIGH_PRIORITY for the first time
  campaign_expanded        a campaign grows materially (>= campaign_alert_growth at once), or any growth of one
                           an analyst has confirmed
  infrastructure_reappears a domain with known-bad ties (campaign member / confirmed neighbour) comes back
                           online or turns hostile again
  risk_increase            a rescore adds >= risk_delta and lands at SUSPICIOUS or above (not the first HIGH)
  provider_failing         an important provider has failed repeatedly

Each alert has a dedupe key and is not raised again inside `cooldown_hours`; suppressed repeats are
counted and returned so they remain visible. Alerts are always stored locally. Outbound delivery is
opt-in (a webhook URL in an environment variable) and carries no personal data: domain, score,
classification and signal names only. A delivery failure is recorded on the alert, never raised.
"""
from __future__ import annotations

import json
import os
from datetime import timedelta, timezone

import httpx

IMPORTANT_PROVIDERS = ("certificate_transparency", "dns", "rdap", "search", "search_discovery", "http")
SEVERITY = {"new_high_priority": "high", "campaign_expanded": "high", "infrastructure_reappears": "high",
            "risk_increase": "medium", "provider_failing": "medium"}
_HOSTILE_CHANGES = {"came_online", "page_turned_hostile", "form_added", "redirect_changed"}


class AlertEngine:
    def __init__(self, store, graph, cfg, post=None, env=None):
        self.store, self.graph, self.cfg, self.ac = store, graph, cfg, cfg.alerts
        self._post = post or self._http_post
        self.env = env if env is not None else os.environ

    # -- cursors ----------------------------------------------------------------------------------------------
    def _cursor(self, name: str) -> int:
        return int(self.store.get_state(f"alerts:{name}").get(f"alerts:{name}", "0"))

    def _set(self, name: str, value: int) -> None:
        self.store.set_state({f"alerts:{name}": str(value)})

    # -- raising ------------------------------------------------------------------------------------------------
    def _raise(self, kind: str, key: str, title: str, detail: dict, *, cid=None, campaign=None, out: dict) -> None:
        cutoff = (self.store.clock() - timedelta(hours=self.ac.cooldown_hours)).astimezone(timezone.utc).isoformat(timespec="microseconds")
        with self.store._lock:
            recent = self.store.conn.execute("SELECT id FROM hunt_alerts WHERE dedupe_key=? AND at>=? LIMIT 1", (key, cutoff)).fetchone()
        if recent:
            out["suppressed"] += 1
            return
        with self.store._tx() as c:
            alert_id = c.execute("INSERT INTO hunt_alerts(at,kind,dedupe_key,severity,title,detail,candidate_id,campaign_id) VALUES(?,?,?,?,?,?,?,?)",
                                 (self.store._iso(), kind, key, SEVERITY[kind], title, json.dumps(detail, sort_keys=True), cid, campaign)).lastrowid
        delivered = self._deliver({"id": alert_id, "kind": kind, "severity": SEVERITY[kind], "title": title, "detail": detail})
        with self.store._tx() as c:
            c.execute("UPDATE hunt_alerts SET delivered=? WHERE id=?", (delivered, alert_id))
        out["raised"].append({"id": alert_id, "kind": kind, "key": key, "title": title, "delivered": delivered})

    def _deliver(self, alert: dict) -> str:
        url = self.env.get(self.ac.webhook_env, "")
        if not url:
            return "local"
        if not url.startswith("https://"):
            return "webhook_refused: not https"
        try:
            self._post(url, alert)
            return "webhook"
        except Exception as exc:
            return f"webhook_failed: {type(exc).__name__}"[:120]

    @staticmethod
    def _http_post(url: str, payload: dict) -> None:
        httpx.post(url, json=payload, timeout=10, follow_redirects=False).raise_for_status()

    # -- evaluation --------------------------------------------------------------------------------------------------
    def evaluate(self) -> dict:
        out = {"raised": [], "suppressed": 0}
        if not self.ac.enabled:
            return out
        self._scores(out)
        self._campaigns(out)
        self._changes(out)
        self._providers(out)
        return out

    def _name(self, cid: str) -> str:
        c = self.store.get(cid)
        return c["canonical"] if c else cid

    def _scores(self, out) -> None:
        last = self._cursor("score_id")
        with self.store._lock:
            rows = self.store.conn.execute("SELECT * FROM hunt_scores WHERE id>? ORDER BY id", (last,)).fetchall()
        for r in rows:
            cid, name = r["candidate_id"], self._name(r["candidate_id"])
            if (self.store.get(cid) or {}).get("disposition") in {"BENIGN", "FALSE_POSITIVE"}:
                last = r["id"]                    # an analyst already cleared it; only new evidence (a change) may re-alert
                continue
            reasons = json.loads(r["reasons"])
            changes = json.loads(r["changes"] or "[]")
            signals = sorted(x["signal"] for x in reasons if x["weight"] > 0)[:8]
            detail = {"domain": name, "score": r["score"], "classification": r["classification"], "signals": signals, "trigger": r["trigger"]}
            with self.store._lock:
                earlier_high = self.store.conn.execute("SELECT 1 FROM hunt_scores WHERE candidate_id=? AND id<? AND classification='HIGH_PRIORITY' LIMIT 1",
                                                       (cid, r["id"])).fetchone()
            if r["classification"] == "HIGH_PRIORITY" and not earlier_high:
                self._raise("new_high_priority", f"high:{cid}", f"New high-priority finding: {name} ({r['score']})", detail, cid=cid, out=out)
            elif r["delta"] is not None and r["delta"] >= self.ac.risk_delta and r["classification"] in {"SUSPICIOUS", "HIGH_PRIORITY"}:
                self._raise("risk_increase", f"risk:{cid}", f"Risk rose {r['delta']:+d} to {r['score']}: {name}", detail, cid=cid, out=out)
            if any(c["signal"] == "known_malicious_infrastructure" and c["change"] == "added" for c in changes):
                self._raise("infrastructure_reappears", f"reuse:{cid}", f"{name} now shares infrastructure with a confirmed domain",
                            detail, cid=cid, out=out)
            last = r["id"]
        self._set("score_id", last)

    def _confirmed(self, campaign_id: str) -> bool:
        confirmed = ",".join("?" * len(self.cfg.scoring.confirmed_verdicts))
        return bool(self.graph.conn.execute(
            f"""SELECT 1 FROM campaign_entities ce JOIN analyst_verdicts v ON v.entity_id=ce.entity_id
                WHERE ce.campaign_id=? AND lower(v.verdict) IN ({confirmed})
                UNION SELECT 1 FROM analyst_verdicts WHERE campaign_id=? AND lower(verdict) IN ({confirmed}) LIMIT 1""",
            (campaign_id, *self.cfg.scoring.confirmed_verdicts, campaign_id, *self.cfg.scoring.confirmed_verdicts)).fetchone())

    def _campaigns(self, out) -> None:
        last = self._cursor("campaign_event_id")
        with self.store._lock:
            rows = self.store.conn.execute("SELECT * FROM hunt_campaign_events WHERE id>? ORDER BY id", (last,)).fetchall()
        for r in rows:
            d = json.loads(r["detail"] or "{}")
            added = len(d.get("added", []))
            if r["event"] in {"expanded", "merged"} and (added >= self.ac_growth() or (added and self._confirmed(r["campaign_id"]))):
                self._raise("campaign_expanded", f"campaign:{r['campaign_id']}",
                            f"Campaign {d.get('public_id')} grew by {added} (now {d.get('members')} domains)",
                            {"campaign": d.get("public_id"), "added": d.get("added"), "members": d.get("members")},
                            campaign=r["campaign_id"], out=out)
            last = r["id"]
        self._set("campaign_event_id", last)

    def ac_growth(self) -> int:
        return self.cfg.correlation.campaign_alert_growth

    def _changes(self, out) -> None:
        last = self._cursor("change_id")
        with self.store._lock:
            rows = self.store.conn.execute("SELECT * FROM hunt_changes WHERE id>? AND meaningful=1 ORDER BY id", (last,)).fetchall()
            top = self.store.conn.execute("SELECT COALESCE(MAX(id),?) FROM hunt_changes", (last,)).fetchone()[0]
        for r in rows:
            cand = self.store.get(r["candidate_id"]) or {}
            known_bad = bool(cand.get("campaign_id")) or (cand.get("classification") in {"SUSPICIOUS", "HIGH_PRIORITY"})
            if r["kind"] in _HOSTILE_CHANGES and known_bad:
                self._raise("infrastructure_reappears", f"change:{r['candidate_id']}:{r['kind']}",
                            f"{cand.get('canonical')}: {r['summary']}", {"domain": cand.get("canonical"), "change": r["kind"],
                                                                          "summary": r["summary"]}, cid=r["candidate_id"], out=out)
        self._set("change_id", top)

    def _providers(self, out) -> None:
        for h in self.store.provider_health():
            if h["provider"] in IMPORTANT_PROVIDERS and h["consecutive_failures"] >= self.ac.provider_failures:
                self._raise("provider_failing", f"provider:{h['provider']}",
                            f"{h['provider']} has failed {h['consecutive_failures']} runs in a row",
                            {"provider": h["provider"], "status": h["status"], "error": (h["last_error"] or "")[:200]}, out=out)

    # -- reading ---------------------------------------------------------------------------------------------------------
    def list(self, limit: int = 100, unacknowledged_only: bool = False) -> list[dict]:
        sql = "SELECT * FROM hunt_alerts" + (" WHERE acknowledged_at IS NULL" if unacknowledged_only else "") + " ORDER BY id DESC LIMIT ?"
        with self.store._lock:
            rows = self.store.conn.execute(sql, (limit,)).fetchall()
        return [{**dict(r), "detail": json.loads(r["detail"] or "{}")} for r in rows]

    def acknowledge(self, alert_id: int, analyst: str) -> bool:
        with self.store._tx() as c:
            return bool(c.execute("UPDATE hunt_alerts SET acknowledged_by=?, acknowledged_at=? WHERE id=? AND acknowledged_at IS NULL",
                                  (analyst, self.store._iso(), alert_id)).rowcount)
