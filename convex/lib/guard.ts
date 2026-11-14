import { ConvexError } from "convex/values";
import { env } from "../_generated/server";

// These functions are called by the Mnara server, never by a browser, and the tables hold
// personal data. A Convex function is reachable by anyone who knows the deployment URL, so
// every one of them takes the shared server key and fails closed when it is missing or unset.
export function assertServer(key: string): void {
  const expected = env.MNARA_SERVER_KEY;
  if (!expected || key !== expected) {
    throw new ConvexError({ code: "UNAUTHORIZED", message: "server key missing or wrong" });
  }
}
