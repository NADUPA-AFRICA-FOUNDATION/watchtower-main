import { v } from "convex/values";
import { mutation, query } from "./_generated/server";
import { assertServer } from "./lib/guard";

export const create = mutation({
  args: {
    key: v.string(),
    kind: v.string(),
    query: v.string(),
    purpose: v.string(),
    user: v.string(),
    platforms: v.array(v.string()),
    now: v.number(),
  },
  returns: v.string(),
  handler: async (ctx, { key, now, ...fields }) => {
    assertServer(key);
    return await ctx.db.insert("runs", { ...fields, created_at: now });
  },
});

export const outcome = mutation({
  args: {
    key: v.string(),
    run_id: v.string(),
    platform: v.string(),
    source: v.string(),
    status: v.string(),
    detail: v.string(),
    count: v.number(),
    now: v.number(),
  },
  returns: v.null(),
  handler: async (ctx, { key, now, detail, ...fields }) => {
    assertServer(key);
    await ctx.db.insert("run_outcomes", { ...fields, detail: detail.slice(0, 300), at: now });
    return null;
  },
});

export const get = query({
  args: { key: v.string(), id: v.string() },
  returns: v.union(v.any(), v.null()),
  handler: async (ctx, { key, id }) => {
    assertServer(key);
    const docId = ctx.db.normalizeId("runs", id);
    const r = docId === null ? null : await ctx.db.get(docId);
    if (r === null) return null;
    const outcomes = await ctx.db.query("run_outcomes").withIndex("by_run", (q) => q.eq("run_id", id)).take(500);
    let pending = 0;
    for (const status of ["pending", "running"] as const) {
      pending += (await ctx.db.query("jobs").withIndex("by_run", (q) => q.eq("run_id", id).eq("status", status)).take(1000)).length;
    }
    return {
      id: r._id as string,
      kind: r.kind,
      query: r.query,
      purpose: r.purpose,
      user: r.user,
      platforms: r.platforms,
      created_at: r.created_at,
      outcomes: outcomes.map(({ platform, source, status, detail, count, at }) => ({ platform, source, status, detail, count, at })),
      pending_jobs: pending,
    };
  },
});
