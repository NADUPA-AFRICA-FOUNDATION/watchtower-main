from datetime import datetime, timedelta, timezone

import pytest

from hunter.store import HuntStore, InvalidTransition


class Clock:
    def __init__(self):
        self.t = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def __call__(self):
        return self.t

    def advance(self, **kw):
        self.t += timedelta(**kw)


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def store(clock):
    return HuntStore(":memory:", clock=clock)


def test_spellings_dedupe_into_one_candidate(store):
    a = store.submit("MPESA-EXAMPLE.COM", "ct")
    b = store.submit("mpesa-example.com/", "search")
    c = store.submit("https://mpesa-example.com", "ct")
    assert a.created and not b.created and not c.created
    assert a.candidate_id == b.candidate_id == c.candidate_id
    row = store.get(a.candidate_id)
    assert row["observation_count"] == 3
    assert row["sources_seen"] == ["ct", "search"]
    assert row["discovery_source"] == "ct"
    assert len(store.observations(a.candidate_id)) == 3
    assert store.stats()["total"] == 1


def test_first_seen_last_seen(store, clock):
    a = store.submit("mpesa-example.com", "ct")
    first = store.get(a.candidate_id)["first_seen"]
    clock.advance(hours=1)
    store.submit("mpesa-example.com", "dns")
    row = store.get(a.candidate_id)
    assert row["first_seen"] == first and row["last_seen"] > first


def test_shallowest_depth_and_highest_priority_win(store):
    a = store.submit("b-example.com", "pivot", depth=3, priority=10, parent_id="p")
    store.submit("b-example.com", "ct", depth=0, priority=40)
    store.submit("b-example.com", "pivot", depth=2, priority=5)
    row = store.get(a.candidate_id)
    assert row["depth"] == 0 and row["priority"] == 40


def test_rejections_are_recorded_not_dropped(store):
    assert not store.submit("not a domain", "search").accepted
    r = store.submit("http://169.254.169.254/latest/meta-data", "page-links")
    assert not r.accepted and "non-public" in r.reason
    assert not store.submit("localhost", "x").accepted
    stats = store.stats()
    assert stats["rejected"] == 3 and stats["total"] == 0
    assert store.rejections()[0]["source"] == "x"


def test_new_then_queued_and_enqueue_false(store):
    a = store.submit("a-example.com", "ct")
    b = store.submit("b-example.com", "ct", enqueue=False)
    assert store.get(a.candidate_id)["status"] == "QUEUED"
    assert store.get(b.candidate_id)["status"] == "NEW"
    assert store.claim(5)[0]["id"] == a.candidate_id and store.claim(5) == []


def test_claim_orders_by_priority_then_depth(store):
    lo = store.submit("lo-example.com", "ct", priority=10)
    deep = store.submit("deep-example.com", "p", priority=50, depth=2)
    top = store.submit("top-example.com", "ct", priority=50, depth=0)
    assert [r["id"] for r in store.claim(3)] == [top.candidate_id, deep.candidate_id, lo.candidate_id]


def test_claim_is_exclusive_across_connections(tmp_path, clock):
    path = tmp_path / "h.db"
    s1, s2 = HuntStore(path, clock=clock), HuntStore(path, clock=clock)
    for i in range(5):
        s1.submit(f"d{i}-example.com", "ct")
    got = [r["id"] for r in s1.claim(3)] + [r["id"] for r in s2.claim(3)]
    assert len(got) == 5 and len(set(got)) == 5


def test_queue_survives_restart(tmp_path, clock):
    path = tmp_path / "h.db"
    s1 = HuntStore(path, clock=clock)
    cid = s1.submit("mpesa-example.com", "ct").candidate_id
    s1.close()
    s2 = HuntStore(path, clock=clock)
    assert s2.get(cid)["status"] == "QUEUED"
    assert s2.claim(1)[0]["id"] == cid


def test_complete_records_score_and_blocks_reclaim(store):
    cid = store.submit("mpesa-example.com", "ct").candidate_id
    store.claim(1)
    store.complete(cid, "SCORED", risk_score=87, campaign_id="c1", note="ok")
    row = store.get(cid)
    assert (row["status"], row["risk_score"], row["campaign_id"]) == ("SCORED", 87, "c1")
    assert row["last_investigated"] and store.claim(1) == []
    store.submit("mpesa-example.com", "search")  # re-sighting must not resurrect it
    assert store.get(cid)["status"] == "SCORED" and store.claim(1) == []


def test_invalid_transitions_raise(store):
    cid = store.submit("mpesa-example.com", "ct").candidate_id
    with pytest.raises(InvalidTransition):
        store.complete(cid, "SCORED")  # QUEUED -> SCORED skips investigation
    with pytest.raises(InvalidTransition):
        store.complete(cid, "FAILED")


def test_retry_backoff_then_failed(store, clock):
    cid = store.submit("mpesa-example.com", "ct").candidate_id
    outcomes = []
    for expected_delay in (60, 120):
        store.claim(1)
        outcomes.append(store.fail(cid, "timeout", max_attempts=3))
        assert store.claim(1) == []  # not due yet
        clock.advance(seconds=expected_delay - 1)
        assert store.claim(1) == []
        clock.advance(seconds=1)
        row = store.get(cid)
        assert row["status"] == "RETRY" and row["error_state"] == "timeout"
    store.claim(1)
    assert store.get(cid)["attempts"] == 3
    outcomes.append(store.fail(cid, "timeout", max_attempts=3))
    assert outcomes == ["RETRY", "RETRY", "FAILED"]
    row = store.get(cid)
    assert row["status"] == "FAILED" and row["error_state"] == "timeout"


def test_backoff_is_capped(store, clock):
    cid = store.submit("mpesa-example.com", "ct").candidate_id
    store.conn.execute("UPDATE hunt_candidates SET attempts=20, status='INVESTIGATING' WHERE id=?", (cid,))
    assert store.fail(cid, "e", max_attempts=99, backoff_cap=300) == "RETRY"
    assert store.get(cid)["next_attempt_at"] == (clock() + timedelta(seconds=300)).isoformat(timespec="microseconds")


def test_defer_keeps_reason_and_gives_attempt_back(store, clock):
    cid = store.submit("mpesa-example.com", "ct").candidate_id
    store.claim(1)
    store.defer(cid, "daily deep-investigation budget reached", clock() + timedelta(hours=1))
    row = store.get(cid)
    assert row["status"] == "QUEUED" and row["attempts"] == 0
    assert row["deferred_reason"] == "daily deep-investigation budget reached"
    assert store.stats()["deferred"] == 1 and store.claim(1) == []
    clock.advance(hours=1, seconds=1)
    assert store.claim(1)[0]["id"] == cid
    assert store.get(cid)["deferred_reason"] is None


def test_recover_stale_claims(store, clock):
    cid = store.submit("mpesa-example.com", "ct").candidate_id
    store.claim(1)
    assert store.recover_stale(900) == 0
    clock.advance(seconds=901)
    assert store.recover_stale(900) == 1
    row = store.get(cid)
    assert row["status"] == "RETRY" and "presumed dead" in row["error_state"]


def test_history_explains_the_candidate(store):
    cid = store.submit("mpesa-example.com", "ct", query="mpesa").candidate_id
    store.claim(1)
    store.complete(cid, "ENRICHED")
    assert [(h["event"], h["to_status"]) for h in store.history(cid)] == [
        ("discovered", "NEW"), ("queued", "QUEUED"), ("claimed", "INVESTIGATING"), ("completed", "ENRICHED")]


def test_requeue_for_deep_pass_resets_attempts(store):
    cid = store.submit("mpesa-example.com", "ct").candidate_id
    store.claim(1)
    store.complete(cid, "ENRICHED")
    store.requeue(cid, priority=80, reason="deep enrich")
    row = store.get(cid)
    assert row["status"] == "QUEUED" and row["priority"] == 80 and row["attempts"] == 0


def test_find_uses_normalization_and_parent_is_kept(store):
    parent = store.submit("a-example.com", "ct").candidate_id
    child = store.submit("+254 700 000 000", "page:a", hint="whatsapp", parent_id=parent, depth=1)
    assert child.indicator_type == "whatsapp" and child.canonical == "+254700000000"
    assert store.find("https://wa.me/254700000000")["parent_id"] == parent
    assert store.find("https://wa.me/254700000000")["depth"] == 1
