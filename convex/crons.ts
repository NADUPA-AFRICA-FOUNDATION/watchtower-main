import { cronJobs } from "convex/server";
import { internal } from "./_generated/api";

const crons = cronJobs();

// Checks every 15 minutes whether the watchlist run (SOCIAL_WATCH_INTERVAL_MINUTES, default
// 360) or the daily purge is due, and queues a job for the Python worker when it is.
crons.interval("queue due social jobs", { minutes: 15 }, internal.jobs.schedule, {});

export default crons;
