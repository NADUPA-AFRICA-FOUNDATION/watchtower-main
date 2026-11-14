/* eslint-disable */
/**
 * Generated `api` utility.
 *
 * THIS CODE IS AUTOMATICALLY GENERATED.
 *
 * To regenerate, run `npx convex dev`.
 * @module
 */

import type * as audit from "../audit.js";
import type * as cache from "../cache.js";
import type * as crons from "../crons.js";
import type * as hits from "../hits.js";
import type * as jobs from "../jobs.js";
import type * as kv from "../kv.js";
import type * as lib_guard from "../lib/guard.js";
import type * as purge from "../purge.js";
import type * as runs from "../runs.js";
import type * as sources from "../sources.js";
import type * as watchlist from "../watchlist.js";

import type {
  ApiFromModules,
  FilterApi,
  FunctionReference,
} from "convex/server";

declare const fullApi: ApiFromModules<{
  audit: typeof audit;
  cache: typeof cache;
  crons: typeof crons;
  hits: typeof hits;
  jobs: typeof jobs;
  kv: typeof kv;
  "lib/guard": typeof lib_guard;
  purge: typeof purge;
  runs: typeof runs;
  sources: typeof sources;
  watchlist: typeof watchlist;
}>;

/**
 * A utility for referencing Convex functions in your app's public API.
 *
 * Usage:
 * ```js
 * const myFunctionReference = api.myModule.myFunction;
 * ```
 */
export declare const api: FilterApi<
  typeof fullApi,
  FunctionReference<any, "public">
>;

/**
 * A utility for referencing Convex functions in your app's internal API.
 *
 * Usage:
 * ```js
 * const myFunctionReference = internal.myModule.myFunction;
 * ```
 */
export declare const internal: FilterApi<
  typeof fullApi,
  FunctionReference<any, "internal">
>;

export declare const components: {};
