import { v } from "convex/values";
import { mutation } from "./_generated/server";
import { assertServer } from "./lib/guard";

const DAY = 86_400_000;
const BATCH = 500; // stays well under the per-mutation write limit; the worker calls again while anything is left

// Retention limit for personal data. Escalated hits are case material and are kept; everything
// else leaves once unseen for the retention period, and dismissed hits leave sooner.
export const run = mutation({
  args: { key: v.string(), now: v.number(), retention_ms: v.number(), dismissed_ms: v.number() },
  returns: v.object({
    dismissed_hits: v.number(),
    expired_hits: v.number(),
    cache_rows: v.number(),
    finished_jobs: v.number(),
    runs: v.number(),
    more: v.boolean(),
  }),
  handler: async (ctx, { key, now, retention_ms, dismissed_ms }) => {
    assertServer(key);
    const removeHit = async (id: (typeof dismissed)[number]["_id"]) => {
      for (const link of await ctx.db.query("run_hits").withIndex("by_hit", (q) => q.eq("hit_id", id)).take(BATCH)) {
        await ctx.db.delete(link._id);
      }
      await ctx.db.delete(id);
    };
    const dismissed = await ctx.db
      .query("hits")
      .withIndex("by_review_reviewed", (q) => q.eq("review_status", "dismissed").lt("reviewed_at", now - dismissed_ms))
      .take(BATCH);
    for (const h of dismissed) await removeHit(h._id);
    const old = await ctx.db.query("hits").withIndex("by_last_seen", (q) => q.lt("last_seen", now - retention_ms)).take(BATCH);
    const expired = old.filter((h) => h.review_status !== "escalated");
    for (const h of expired) await removeHit(h._id);
    const cache = await ctx.db.query("http_cache").withIndex("by_expires", (q) => q.lt("expires_at", now)).take(BATCH);
    for (const c of cache) await ctx.db.delete(c._id);
    let jobs = 0;
    for (const status of ["done", "failed"] as const) {
      const rows = await ctx.db
        .query("jobs")
        .withIndex("by_status_finished", (q) => q.eq("status", status).lt("finished_at", now - 7 * DAY))
        .take(BATCH);
      for (const j of rows) await ctx.db.delete(j._id);
      jobs += rows.length;
    }
    const events = await ctx.db.query("source_events").withIndex("by_at", (q) => q.lt("at", now - 8 * DAY)).take(BATCH);
    for (const e of events) await ctx.db.delete(e._id);
    const runs = await ctx.db.query("runs").withIndex("by_created", (q) => q.lt("created_at", now - retention_ms)).take(BATCH);
    for (const r of runs) {
      for (const o of await ctx.db.query("run_outcomes").withIndex("by_run", (q) => q.eq("run_id", r._id)).take(BATCH)) {
        await ctx.db.delete(o._id);
      }
      await ctx.db.delete(r._id);
    }
    const more = [dismissed, old, cache, events, runs].some((rows) => rows.length === BATCH);
    return { dismissed_hits: dismissed.length, expired_hits: expired.length, cache_rows: cache.length, finished_jobs: jobs, runs: runs.length, more };
  },
});
