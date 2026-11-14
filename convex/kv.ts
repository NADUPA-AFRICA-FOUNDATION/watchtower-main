import { v } from "convex/values";
import { mutation, query } from "./_generated/server";
import { assertServer } from "./lib/guard";

export const get = query({
  args: { key: v.string(), name: v.string() },
  returns: v.union(v.string(), v.null()),
  handler: async (ctx, { key, name }) => {
    assertServer(key);
    return (await ctx.db.query("kv").withIndex("by_key", (q) => q.eq("key", name)).unique())?.value ?? null;
  },
});

export const set = mutation({
  args: { key: v.string(), name: v.string(), value: v.string() },
  returns: v.null(),
  handler: async (ctx, { key, name, value }) => {
    assertServer(key);
    const row = await ctx.db.query("kv").withIndex("by_key", (q) => q.eq("key", name)).unique();
    if (row === null) await ctx.db.insert("kv", { key: name, value });
    else await ctx.db.patch(row._id, { value });
    return null;
  },
});
