import { v } from "convex/values";
import { Doc, Id } from "./_generated/dataModel";
import { mutation, query, QueryCtx } from "./_generated/server";
import { assertServer } from "./lib/guard";

const REVIEW = v.union(v.literal("new"), v.literal("relevant"), v.literal("dismissed"), v.literal("escalated"));
const BOOKKEEPING = new Set(["id", "review_status", "first_seen", "last_seen", "reviewed_by", "reviewed_at"]);

function view(h: Doc<"hits">) {
  return {
    ...h.doc,
    id: h._id as string,
    review_status: h.review_status,
    first_seen: h.first_seen,
    last_seen: h.last_seen,
    reviewed_by: h.reviewed_by ?? null,
    reviewed_at: h.reviewed_at ?? null,
  };
}

export const get = query({
  args: { key: v.string(), id: v.string() },
  returns: v.union(v.any(), v.null()),
  handler: async (ctx, { key, id }) => {
    assertServer(key);
    const docId = ctx.db.normalizeId("hits", id);
    const h = docId === null ? null : await ctx.db.get(docId);
    return h === null ? null : view(h);
  },
});

export const getByUrl = query({
  args: { key: v.string(), url: v.string() },
  returns: v.union(v.any(), v.null()),
  handler: async (ctx, { key, url }) => {
    assertServer(key);
    const h = await ctx.db.query("hits").withIndex("by_url", (q) => q.eq("url", url)).unique();
    return h === null ? null : view(h);
  },
});

// Insert, or replace the document of the hit with this URL. Review state and first_seen survive.
export const put = mutation({
  args: { key: v.string(), doc: v.any(), now: v.number(), run_id: v.optional(v.string()) },
  returns: v.object({ id: v.string(), created: v.boolean() }),
  handler: async (ctx, { key, doc, now, run_id }) => {
    assertServer(key);
    const body = Object.fromEntries(Object.entries(doc as Record<string, unknown>).filter(([k]) => !BOOKKEEPING.has(k)));
    const author = (doc.author ?? {}) as Record<string, unknown>;
    const content = (doc.content ?? {}) as Record<string, unknown>;
    const columns = {
      platform: String(doc.platform),
      url: String(doc.url),
      author_handle: typeof author.username === "string" ? author.username : undefined,
      text: typeof content.text === "string" ? content.text : undefined,
      published_at: typeof content.published_at === "string" ? content.published_at : undefined,
      matched_terms: Array.isArray(doc.matched_terms) ? doc.matched_terms.map(String) : [],
      engagement: doc.engagement ?? {},
      source_method: String(doc.source_method),
      confidence: Number(doc.confidence ?? 0),
      score: Number(doc.score ?? 0),
      status: String(doc.status),
      last_seen: now,
      doc: body,
    };
    const existing = await ctx.db.query("hits").withIndex("by_url", (q) => q.eq("url", columns.url)).unique();
    let id: Id<"hits">;
    let created = false;
    if (existing !== null) {
      id = existing._id;
      await ctx.db.patch(id, columns);
    } else {
      id = await ctx.db.insert("hits", { ...columns, review_status: "new", first_seen: now });
      created = true;
    }
    if (run_id !== undefined) {
      const link = await ctx.db.query("run_hits").withIndex("by_run", (q) => q.eq("run_id", run_id).eq("hit_id", id)).unique();
      if (link === null) await ctx.db.insert("run_hits", { run_id, hit_id: id });
    }
    return { id, created };
  },
});

async function forRun(ctx: QueryCtx, run_id: string): Promise<Doc<"hits">[]> {
  const links = await ctx.db.query("run_hits").withIndex("by_run", (q) => q.eq("run_id", run_id)).take(500);
  const rows = await Promise.all(links.map((l) => ctx.db.get(l.hit_id)));
  return rows.filter((r): r is Doc<"hits"> => r !== null);
}

export const list = query({
  args: {
    key: v.string(),
    review_status: v.optional(REVIEW),
    platform: v.optional(v.string()),
    run_id: v.optional(v.string()),
    limit: v.number(),
  },
  returns: v.array(v.any()),
  handler: async (ctx, { key, review_status, platform, run_id, limit }) => {
    assertServer(key);
    const cap = Math.max(1, Math.min(Math.floor(limit), 500));
    let rows: Doc<"hits">[];
    if (run_id !== undefined) {
      rows = await forRun(ctx, run_id);
    } else if (review_status !== undefined) {
      rows = await ctx.db
        .query("hits")
        .withIndex("by_review_score", (q) => q.eq("review_status", review_status))
        .order("desc")
        .take(platform ? 2000 : cap);
    } else {
      rows = await ctx.db.query("hits").withIndex("by_score").order("desc").take(platform ? 2000 : cap);
    }
    if (review_status !== undefined) rows = rows.filter((r) => r.review_status === review_status);
    if (platform) rows = rows.filter((r) => r.platform === platform);
    rows.sort((a, b) => b.score - a.score || b.last_seen - a.last_seen);
    return rows.slice(0, cap).map(view);
  },
});

export const review = mutation({
  args: { key: v.string(), id: v.string(), review_status: REVIEW, user: v.string(), now: v.number() },
  returns: v.boolean(),
  handler: async (ctx, { key, id, review_status, user, now }) => {
    assertServer(key);
    const docId = ctx.db.normalizeId("hits", id);
    if (docId === null || (await ctx.db.get(docId)) === null) return false;
    await ctx.db.patch(docId, { review_status, reviewed_by: user, reviewed_at: now });
    return true;
  },
});
