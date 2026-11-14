import { v } from "convex/values";
import { mutation, query } from "./_generated/server";
import { assertServer } from "./lib/guard";

const row = v.object({
  id: v.string(),
  term: v.string(),
  match_type: v.string(),
  platforms: v.array(v.string()),
  active: v.boolean(),
  created_by: v.string(),
  created_at: v.number(),
});

export const add = mutation({
  args: {
    key: v.string(),
    term: v.string(),
    match_type: v.union(v.literal("exact"), v.literal("fuzzy")),
    platforms: v.array(v.string()),
    created_by: v.string(),
    now: v.number(),
  },
  returns: row,
  handler: async (ctx, { key, now, ...fields }) => {
    assertServer(key);
    const id = await ctx.db.insert("watchlist", { ...fields, active: true, created_at: now });
    return { id, ...fields, active: true, created_at: now };
  },
});

export const list = query({
  args: { key: v.string(), active_only: v.boolean() },
  returns: v.array(row),
  handler: async (ctx, { key, active_only }) => {
    assertServer(key);
    const rows = active_only
      ? await ctx.db.query("watchlist").withIndex("by_active", (q) => q.eq("active", true)).take(500)
      : await ctx.db.query("watchlist").take(500);
    return rows
      .sort((a, b) => a.created_at - b.created_at)
      .map((w) => ({
        id: w._id as string,
        term: w.term,
        match_type: w.match_type,
        platforms: w.platforms,
        active: w.active,
        created_by: w.created_by,
        created_at: w.created_at,
      }));
  },
});

export const update = mutation({
  args: { key: v.string(), id: v.string(), active: v.boolean() },
  returns: v.boolean(),
  handler: async (ctx, { key, id, active }) => {
    assertServer(key);
    const docId = ctx.db.normalizeId("watchlist", id);
    if (docId === null || (await ctx.db.get(docId)) === null) return false;
    await ctx.db.patch(docId, { active });
    return true;
  },
});

export const remove = mutation({
  args: { key: v.string(), id: v.string() },
  returns: v.boolean(),
  handler: async (ctx, { key, id }) => {
    assertServer(key);
    const docId = ctx.db.normalizeId("watchlist", id);
    if (docId === null || (await ctx.db.get(docId)) === null) return false;
    await ctx.db.delete(docId);
    return true;
  },
});
