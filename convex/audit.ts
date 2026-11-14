import { v } from "convex/values";
import { mutation, query } from "./_generated/server";
import { assertServer } from "./lib/guard";

export const add = mutation({
  args: {
    key: v.string(),
    user: v.string(),
    action: v.string(),
    query: v.string(),
    sources_used: v.array(v.string()),
    purpose: v.string(),
    now: v.number(),
  },
  returns: v.null(),
  handler: async (ctx, { key, now, ...fields }) => {
    assertServer(key);
    await ctx.db.insert("audit", { ...fields, at: now });
    return null;
  },
});

export const list = query({
  args: { key: v.string(), limit: v.number() },
  returns: v.array(
    v.object({ user: v.string(), action: v.string(), query: v.string(), sources_used: v.array(v.string()), purpose: v.string(), at: v.number() }),
  ),
  handler: async (ctx, { key, limit }) => {
    assertServer(key);
    const rows = await ctx.db.query("audit").withIndex("by_at").order("desc").take(Math.max(1, Math.min(Math.floor(limit), 500)));
    return rows.map(({ user, action, query, sources_used, purpose, at }) => ({ user, action, query, sources_used, purpose, at }));
  },
});
