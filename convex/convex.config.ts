import { defineApp } from "convex/server";
import { v } from "convex/values";

// MNARA_SERVER_KEY: shared secret between the Mnara Python services and these functions.
// Every function checks it, because the tables hold personal data and a Convex deployment URL
// is reachable by anyone who has it. Set with `npx convex env set MNARA_SERVER_KEY <value>`.
const app = defineApp({
  env: {
    MNARA_SERVER_KEY: v.optional(v.string()),
    SOCIAL_WATCH_INTERVAL_MINUTES: v.optional(v.string()),
  },
});
export default app;
