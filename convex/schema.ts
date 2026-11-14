import { defineSchema, defineTable } from "convex/server";
import { v } from "convex/values";

// Social discovery tables. Mirrors social/store.py (the SQLite fallback) one for one.
// All times are milliseconds since the epoch, supplied by the caller.
export default defineSchema({
  watchlist: defineTable({
    term: v.string(),
    match_type: v.union(v.literal("exact"), v.literal("fuzzy")),
    platforms: v.array(v.string()),
    active: v.boolean(),
    created_by: v.string(),
    created_at: v.number(),
  }).index("by_active", ["active"]),

  jobs: defineTable({
    kind: v.string(),
    payload: v.any(),
    status: v.union(v.literal("pending"), v.literal("running"), v.literal("done"), v.literal("failed")),
    attempts: v.number(),
    run_after: v.number(),
    locked_at: v.optional(v.number()),
    dedupe_key: v.optional(v.string()),
    run_id: v.optional(v.string()),
    error: v.optional(v.string()),
    created_at: v.number(),
    finished_at: v.optional(v.number()),
  })
    .index("by_status_run_after", ["status", "run_after"])
    .index("by_status_locked", ["status", "locked_at"])
    .index("by_status_finished", ["status", "finished_at"])
    .index("by_dedupe", ["dedupe_key", "status"])
    .index("by_run", ["run_id", "status"]),

  http_cache: defineTable({
    key: v.string(),
    body: v.string(),
    status: v.number(),
    fetched_at: v.number(),
    expires_at: v.number(),
  })
    .index("by_key", ["key"])
    .index("by_expires", ["expires_at"]),

  hits: defineTable({
    platform: v.string(),
    url: v.string(),
    author_handle: v.optional(v.string()),
    text: v.optional(v.string()),
    published_at: v.optional(v.string()),
    matched_terms: v.array(v.string()),
    engagement: v.any(),
    source_method: v.string(),
    confidence: v.number(),
    score: v.number(),
    status: v.string(),
    review_status: v.union(v.literal("new"), v.literal("relevant"), v.literal("dismissed"), v.literal("escalated")),
    first_seen: v.number(),
    last_seen: v.number(),
    reviewed_by: v.optional(v.string()),
    reviewed_at: v.optional(v.number()),
    doc: v.any(), // the unified hit document, including score reasons and the verdict
  })
    .index("by_url", ["url"])
    .index("by_score", ["score"])
    .index("by_review_score", ["review_status", "score"])
    .index("by_review_reviewed", ["review_status", "reviewed_at"])
    .index("by_last_seen", ["last_seen"]),

  run_hits: defineTable({ run_id: v.string(), hit_id: v.id("hits") })
    .index("by_run", ["run_id", "hit_id"])
    .index("by_hit", ["hit_id"]),

  audit: defineTable({
    user: v.string(),
    action: v.string(),
    query: v.string(),
    sources_used: v.array(v.string()),
    purpose: v.string(),
    at: v.number(),
  }).index("by_at", ["at"]),

  sources: defineTable({
    source: v.string(),
    last_success_at: v.optional(v.number()),
    last_failure_at: v.optional(v.number()),
    consecutive_failures: v.number(),
    breaker_until: v.optional(v.number()),
    last_status: v.string(),
    last_detail: v.string(),
  }).index("by_source", ["source"]),

  source_events: defineTable({ source: v.string(), ok: v.boolean(), at: v.number() })
    .index("by_source_at", ["source", "at"])
    .index("by_at", ["at"]),

  runs: defineTable({
    kind: v.string(),
    query: v.string(),
    purpose: v.string(),
    user: v.string(),
    platforms: v.array(v.string()),
    created_at: v.number(),
  }).index("by_created", ["created_at"]),

  run_outcomes: defineTable({
    run_id: v.string(),
    platform: v.string(),
    source: v.string(),
    status: v.string(),
    detail: v.string(),
    count: v.number(),
    at: v.number(),
  }).index("by_run", ["run_id", "at"]),

  kv: defineTable({ key: v.string(), value: v.string() }).index("by_key", ["key"]),
});
