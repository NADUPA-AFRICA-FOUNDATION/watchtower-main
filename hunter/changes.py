"""Historical change detection.

Evidence is append-only, so the history of a domain is already stored: this compares the latest
two observations of each kind and records what differs. A parked domain that becomes an M-PESA login
page is the case it exists for; the earlier "parked" evidence is never overwritten.

`meaningful` marks changes an analyst should hear about (came online, new credential form, moved hosts,
redirect target changed, content removed). Everything else (a renewed certificate, a changed body hash)
is still recorded, quietly.
"""
from __future__ import annotations

import json

MATERIAL_FLAGS = ("credential_form", "solicits_pin", "solicits_otp", "solicits_card", "cross_origin_form", "whatsapp_cta",
                  "telegram_cta", "payment_instruction", "fee_language", "guaranteed_returns", "crypto_wallet",
                  "credential_language")
_KEYED = {"page_signals", "http_response"}
_TYPES = ("dns_lookup", "rdap_lookup", "tls_lookup", "http_response", "page_signals")


def _facts(row) -> dict:
    try:
        v = json.loads(row["observed_value"])
        return v if isinstance(v, dict) else {}
    except (ValueError, TypeError):
        return {}


def _diff(kind: str, before: dict, after: dict) -> list[tuple]:
    """(change_kind, meaningful, summary, before, after) tuples."""
    out = []
    if kind == "dns_lookup":
        if before.get("status") != after.get("status"):
            went_up = after.get("status") == "resolved" and before.get("status") in {"nxdomain", "no_address"}
            out.append(("came_online" if went_up else "dns_status", True,
                        f"DNS went from {before.get('status')} to {after.get('status')}", before.get("status"), after.get("status")))
        for rtype in ("A", "AAAA", "NS", "MX"):
            b, a = before.get("records", {}).get(rtype), after.get("records", {}).get(rtype)
            if b is not None and a is not None and b != a and (b or a) and before.get("status") == after.get("status"):
                out.append((f"dns_{rtype.lower()}", rtype in {"A", "AAAA", "NS"},
                            f"{rtype} records changed: {b} -> {a}", b, a))
    elif kind == "rdap_lookup":
        for key, label, meaningful in (("registrar", "registrar", True), ("statuses", "registry status", True),
                                       ("nameservers", "nameservers", True), ("registered_at", "registration date (re-registered?)", True)):
            if before.get(key) != after.get(key):
                out.append((f"rdap_{key}", meaningful, f"{label} changed: {before.get(key)} -> {after.get(key)}", before.get(key), after.get(key)))
    elif kind == "tls_lookup":
        if before.get("status") != after.get("status"):
            out.append(("tls_status", True, f"TLS went from {before.get('status')} to {after.get('status')}", before.get("status"), after.get("status")))
        elif before.get("fingerprint") != after.get("fingerprint"):
            out.append(("tls_certificate", False, "certificate changed", before.get("fingerprint"), after.get("fingerprint")))
    elif kind == "http_response":
        if before.get("status") != after.get("status") or before.get("error_kind") != after.get("error_kind"):
            out.append(("http_status", True, f"page went from {before.get('error_kind') or before.get('status')} to "
                        f"{after.get('error_kind') or after.get('status')}", before.get("status"), after.get("status")))
        bh, ah = (before.get("final_url") or "").split("/")[2:3], (after.get("final_url") or "").split("/")[2:3]
        if bh and ah and bh != ah:
            out.append(("redirect_changed", True, f"final host changed: {bh[0]} -> {ah[0]}", bh[0], ah[0]))
        if before.get("title") != after.get("title") and after.get("title"):
            out.append(("title_changed", True, f"page title changed: {before.get('title')!r} -> {after.get('title')!r}",
                        before.get("title"), after.get("title")))
        if len(after.get("forms") or []) > len(before.get("forms") or []):
            out.append(("form_added", True, f"forms on page: {len(before.get('forms') or [])} -> {len(after.get('forms') or [])}",
                        len(before.get("forms") or []), len(after.get("forms") or [])))
        elif before.get("body_sha256") != after.get("body_sha256") and not out:
            out.append(("content_changed", False, "page content changed", before.get("body_sha256"), after.get("body_sha256")))
    elif kind == "page_signals":
        bf, af = before.get("flags", {}), after.get("flags", {})
        turned_on = [f for f in MATERIAL_FLAGS if af.get(f) and not bf.get(f)]
        turned_off = [f for f in MATERIAL_FLAGS if bf.get(f) and not af.get(f)]
        if turned_on:
            out.append(("page_turned_hostile", True, "page now shows: " + ", ".join(turned_on), sorted(bf), sorted(af)))
        if turned_off and not turned_on:
            out.append(("page_cleaned", True, "page no longer shows: " + ", ".join(turned_off), sorted(bf), sorted(af)))
        if bf.get("content_unassessed") and not af.get("content_unassessed"):
            out.append(("page_now_assessable", True, "page content could be read this time", None, None))
    return out


def detect_changes(store, graph, cid: str) -> list[dict]:
    """Compare the newest two observations of each kind for one domain; record what changed."""
    rows = graph.conn.execute("SELECT * FROM evidence WHERE entity_id=? AND evidence_type IN (%s) ORDER BY observed_at, rowid"
                              % ",".join("?" * len(_TYPES)), (cid, *_TYPES)).fetchall()
    series: dict[tuple, list] = {}
    for r in rows:
        series.setdefault((r["evidence_type"], r["source_url"] if r["evidence_type"] in _KEYED else ""), []).append(r)
    found = []
    for (kind, _), items in series.items():
        if len(items) < 2:
            continue
        prev, cur = items[-2], items[-1]
        for change, meaningful, summary, before, after in _diff(kind, _facts(prev), _facts(cur)):
            if store.add_change(cid, change, summary, meaningful=meaningful, before=before, after=after, evidence_id=cur["id"]):
                found.append({"kind": change, "meaningful": meaningful, "summary": summary, "evidence_id": cur["id"]})
    return found
