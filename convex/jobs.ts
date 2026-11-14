import { v } from "convex/values";
import { Doc } from "./_generated/dataModel";
import { env, internalMutation, mutation, query } from "./_generated/server";
import { assertServer } from "./lib/guard";

const job = v.object({
  id: v.string(),
  kind: v.string(),
  payload: v.any(),
  status: v.string(),
  attempts: v.number(),
  run_after: v.number(),
  locked_at: v.union(v.number(), v.null()),
  run_id: v.union(v.string(), v.null()),
  error: v.union(v.string(), v.null()),
});

function view(j: Doc<"jobs">) {
  return {
    id: j._id as string,
    kind: j.kind,
    payload: j.payload,
    status: j.status,
    attempts: j.attempts,
    run_after: j.run_after,
    locked_at: j.locked_at ?? null,
    run_id: j.run_id ?? null,
    error: j.error ?? null,
  };
}

export const enqueue = mutation({
  args: {
    key: v.string(),
    kind: v.string(),
    payload: v.any(),
    now: v.number(),
    run_after: v.optional(v.number()),
    dedupe_key: v.optional(v.string()),
    run_id: v.optional(v.string()),
  },
  returns: v.union(v.string(), v.null()),
  handler: async (ctx, { key, kind, payload, now, run_after, dedupe_key, run_id }) => {
    assertServer(key);
    if (dedupe_key !== undefined) {
      for (const status of ["pending", "running"] as const) {
        const dup = await ctx.db
          .query("jobs")
          .withIndex("by_dedupe", (q) => q.eq("dedupe_key", dedupe_key).eq("status", status))
          .first();
        if (dup !== null) return null;
      }
    }
    return await ctx.db.insert("jobs", {
      kind,
      payload,
      status: "pending",
      attempts: 0,
      run_after: run_after ?? now,
      dedupe_key,
      run_id,
      created_at: now,
    });
  },
});

// A mutation is one serializable transaction, so two workers can never claim the same job:
// this is what SELECT ... FOR UPDATE SKIP LOCKED was standing in for.
export const claim = mutation({
  args: { key: v.string(), now: v.number(), lock_ms: v.number() },
  returns: v.union(job, v.null()),
  handler: async (ctx, { key, now, lock_ms }) => {
    assertServer(key);
    const due = await ctx.db
      .query("jobs")
      .withIndex("by_status_run_after", (q) => q.eq("status", "pending").lte("run_after", now))
      .first();
    // A running job whose worker died is taken over once its lock is older than lock_ms.
    // Between a due job and a stale one, the one that has waited longest (earliest run_after)
    // goes first, the same order the SQLite store uses.
    const stale = await ctx.db
      .query("jobs")
      .withIndex("by_status_locked", (q) => q.eq("status", "running").lt("locked_at", now - lock_ms))
      .take(50);
    const oldestStale = stale.reduce<Doc<"jobs"> | null>((a, b) => (a === null || b.run_after < a.run_after ? b : a), null);
    const next = due === null ? oldestStale : oldestStale !== null && oldestStale.run_after < due.run_after ? oldestStale : due;
    if (next === null) return null;
    await ctx.db.patch(next._id, { status: "running", locked_at: now, attempts: next.attempts + 1 });
    return view({ ...next, status: "running", locked_at: now, attempts: next.attempts + 1 });
  },
});

export const finish = mutation({
  args: { key: v.string(), id: v.string(), ok: v.boolean(), error: v.optional(v.string()), now: v.number() },
  returns: v.null(),
  handler: async (ctx, { key, id, ok, error, now }) => {
    assertServer(key);
    const docId = ctx.db.normalizeId("jobs", id);
    if (docId === null || (await ctx.db.get(docId)) === null) return null;
    await ctx.db.patch(docId, { status: ok ? "done" : "failed", error, finished_at: now, locked_at: undefined });
    return null;
  },
});

export const retry = mutation({
  args: { key: v.string(), id: v.string(), run_after: v.number(), error: v.optional(v.string()) },
  returns: v.null(),
  handler: async (ctx, { key, id, run_after, error }) => {
    assertServer(key);
    const docId = ctx.db.normalizeId("jobs", id);
    if (docId === null || (await ctx.db.get(docId)) === null) return null;
    await ctx.db.patch(docId, { status: "pending", run_after, error, locked_at: undefined });
    return null;
  },
});

export const pending = query({
  args: { key: v.string(), run_id: v.optional(v.string()) },
  returns: v.number(),
  handler: async (ctx, { key, run_id }) => {
    assertServer(key);
    let n = 0;
    for (const status of ["pending", "running"] as const) {
      const rows =
        run_id !== undefined
          ? await ctx.db.query("jobs").withIndex("by_run", (q) => q.eq("run_id", run_id).eq("status", status)).take(1000)
          : await ctx.db.query("jobs").withIndex("by_status_run_after", (q) => q.eq("status", status)).take(1000);
      n += rows.length;
    }
    return n;
  },
});

// Called by the cron. The logic of a watchlist run and of the purge lives in the Python
// worker; scheduling them is all Convex does, so there is one implementation of each.
export const schedule = internalMutation({
  args: {},
  returns: v.null(),
  handler: async (ctx) => {
    const now = Date.now();
    const minutes = Number(env.SOCIAL_WATCH_INTERVAL_MINUTES ?? "360") || 360;
    for (const [name, kind, every] of [
      ["last_watchlist_at", "watchlist", minutes * 60_000],
      ["last_purge_at", "purge", 86_400_000],
    ] as const) {
      const stamp = await ctx.db.query("kv").withIndex("by_key", (q) => q.eq("key", name)).unique();
      if (stamp !== null && now - Number(stamp.value) < every) continue;
      const open = await ctx.db
        .query("jobs")
        .withIndex("by_dedupe", (q) => q.eq("dedupe_key", kind).eq("status", "pending"))
        .first();
      if (open === null) {
        await ctx.db.insert("jobs", { kind, payload: {}, status: "pending", attempts: 0, run_after: now, dedupe_key: kind, created_at: now });
      }
      if (stamp === null) await ctx.db.insert("kv", { key: name, value: String(now) });
      else await ctx.db.patch(stamp._id, { value: String(now) });
    }
    return null;
  },
});
