import { v } from "convex/values";
import { mutation, query } from "./_generated/server";
import { assertServer } from "./lib/guard";

export const get = query({
  args: { key: v.string(), cache_key: v.string(), now: v.number() },
  returns: v.union(v.object({ body: v.string(), status: v.number(), fetched_at: v.number() }), v.null()),
  handler: async (ctx, { key, cache_key, now }) => {
    assertServer(key);
    const row = await ctx.db.query("http_cache").withIndex("by_key", (q) => q.eq("key", cache_key)).unique();
    if (row === null || row.expires_at <= now) return null;
    return { body: row.body, status: row.status, fetched_at: row.fetched_at };
  },
});

export const put = mutation({
  args: { key: v.string(), cache_key: v.string(), body: v.string(), status: v.number(), now: v.number(), ttl_ms: v.number() },
  returns: v.null(),
  handler: async (ctx, { key, cache_key, body, status, now, ttl_ms }) => {
    assertServer(key);
    // A Convex document is capped at 1 MiB; a page bigger than that is simply not cached.
    if (body.length > 900_000) return null;
    const row = await ctx.db.query("http_cache").withIndex("by_key", (q) => q.eq("key", cache_key)).unique();
    const fields = { key: cache_key, body, status, fetched_at: now, expires_at: now + ttl_ms };
    if (row === null) await ctx.db.insert("http_cache", fields);
    else await ctx.db.replace(row._id, fields);
    return null;
  },
});
