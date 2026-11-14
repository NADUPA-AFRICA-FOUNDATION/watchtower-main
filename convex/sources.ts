import { v } from "convex/values";
import { mutation, query } from "./_generated/server";
import { assertServer } from "./lib/guard";

const DAY = 86_400_000;

// One attempt. After `threshold` failures in a row the source is paused; each further failure
// doubles the pause up to the maximum; one success closes the breaker. Same rule as social/store.py.
export const event = mutation({
  args: {
    key: v.string(),
    source: v.string(),
    ok: v.boolean(),
    status: v.string(),
    detail: v.string(),
    now: v.number(),
    threshold: v.number(),
    base_ms: v.number(),
    max_ms: v.number(),
  },
  returns: v.object({ consecutive_failures: v.number(), breaker_until: v.union(v.number(), v.null()) }),
  handler: async (ctx, { key, source, ok, status, detail, now, threshold, base_ms, max_ms }) => {
    assertServer(key);
    const row = await ctx.db.query("sources").withIndex("by_source", (q) => q.eq("source", source)).unique();
    const fails = ok ? 0 : (row?.consecutive_failures ?? 0) + 1;
    const until = fails >= threshold ? now + Math.min(max_ms, base_ms * 2 ** (fails - threshold)) : undefined;
    const fields = {
      source,
      consecutive_failures: fails,
      breaker_until: until,
      last_status: status,
      last_detail: detail.slice(0, 300),
      last_success_at: ok ? now : row?.last_success_at,
      last_failure_at: ok ? row?.last_failure_at : now,
    };
    if (row === null) await ctx.db.insert("sources", fields);
    else await ctx.db.replace(row._id, fields);
    await ctx.db.insert("source_events", { source, ok, at: now });
    return { consecutive_failures: fails, breaker_until: until ?? null };
  },
});

export const health = query({
  args: { key: v.string(), now: v.number() },
  returns: v.array(v.any()),
  handler: async (ctx, { key, now }) => {
    assertServer(key);
    const rows = await ctx.db.query("sources").take(100);
    rows.sort((a, b) => a.source.localeCompare(b.source));
    return await Promise.all(
      rows.map(async (r) => {
        const events = await ctx.db
          .query("source_events")
          .withIndex("by_source_at", (q) => q.eq("source", r.source).gt("at", now - 7 * DAY))
          .take(5000);
        const ok = events.filter((e) => e.ok).length;
        const open = r.breaker_until !== undefined && r.breaker_until > now;
        return {
          source: r.source,
          last_success_at: r.last_success_at ?? null,
          last_failure_at: r.last_failure_at ?? null,
          consecutive_failures: r.consecutive_failures,
          breaker: open ? "open" : "closed",
          breaker_until: open ? r.breaker_until : null,
          last_status: r.last_status,
          last_detail: r.last_detail,
          attempts_7d: events.length,
          success_rate_7d: events.length ? Math.round((ok / events.length) * 1000) / 1000 : null,
        };
      }),
    );
  },
});
