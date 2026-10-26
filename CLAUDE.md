# CLAUDE.md

Context for Claude Code sessions in this repo. Read this before changing anything.

## What this is

**Two separate engines behind one front door, plus an autonomous hunter on the watchtower side
(`hunter/`, see `HUNTER.md`).** They share the Python
environment, the `.env`, the house style, and — since the merge — the web UI,
which has a watchtower side and a scamscan side. Nothing below that is shared:
no shared database, no shared config, and the dependency runs one way only.
`web/app.py` imports both; **`scamscan.py` imports nothing from `core/`, and
`core/` imports nothing from `scamscan`**. A shared front door is not a shared
engine, and the moment one tool reaches into the other's store or config that
stops being true. Read the section for the one you're working on.

| | **watchtower** | **scamscan** |
|---|---|---|
| Question | "what is being said about X?" | "who is running scams against brand X?" |
| Entry | `run.py` (+ web UI: Sweep, Archive) | `scamscan.py` (+ web UI: Queue, Score) |
| Config | `config.yaml` | `config.json` |
| Store | `watchtower.db` | `scamscan.db` |
| Docs | `README.md` | `SCAMSCAN.md` |
| Tests | `smoke_test.py`, `sweep_test.py`, `web_test.py` | `scamscan_test.py` |
| Search | 13 backends in `core/sources.py` | Claude's server-side web search |

**watchtower** — a monitoring tool for open-source research. Type a keyword, get
ranked findings from news, regulatory sources, social and sanctions lists. Two
front doors: a web UI and a CLI. Same pipeline behind both. Built for AML/CFT
compliance research (adverse media, regulatory change tracking, entity
screening), but nothing in the code is compliance-specific.

**scamscan** — keyword-driven scam discovery. Claude proposes candidate pages
via server-side web search; local Python code scores them across four
independent families (lexicon, artifact, impersonation, model confidence).
See `## scamscan` below for its own invariants.

## Commands

```bash
pip install -r requirements.txt

# watchtower
python run.py serve                          # web UI, localhost:8000
python run.py sweep "query" --hours 168      # CLI sweep
python run.py run                            # scheduled mode: collect+enrich+alert
python run.py search "kenya AND fraud"       # FTS5 over the archive
python run.py sources                        # list backends
python run.py stats
python diagnose.py                           # why did every source return zero?

# scamscan  (costs money per run — start with one topic)
python scamscan.py hunt --config config.json --topics 1
python scamscan.py hunt --topics 1 --dry-run   # queries only: no search, no cost
python scamscan.py models                      # what this key can reach
python scamscan.py queue --min-score 45
python scamscan.py test "<text>" --url <url>   # offline scoring, no API calls
python scamscan.py selftest                    # schema lint, tool version, lexicon audit
python scamscan.py selftest --live             # ~1 search: does the schema survive web search?

# autonomous hunter (HUNTER.md; own config hunter.yaml, own store hunter.db)
python run.py hunt                           # the scheduler; --once runs every job once
python -m hunter coverage                    # source health. Also: explain, lineage, campaigns, alerts, rescore, purge ...
python -m pytest -q                          # hunter + investigation + security suites (offline)

# tests — all four, no network, no API key, seconds
python smoke_test.py     # watchtower: store, dedupe, FTS5, alerts
python sweep_test.py     # watchtower: backends, ranking, renderers, concurrency
python web_test.py       # watchtower: endpoints, SSE, frontend wiring
python scamscan_test.py  # scamscan: scoring, lexicon, schemas, silent-failure detection
```

Each suite prints its own total; don't hardcode the counts here, they drift.
`diagnose.py` is the first thing to run when a sweep comes back empty — it
reports the actual HTTP status and robots verdict per endpoint.

**Run all four tests after any change.** They use `httpx.MockTransport`, so
they need no network and no API key, and they finish in seconds. If you change
an SSE event name, a CSS class the JS applies, or an element ID, `web_test.py`
catches it — that's what its frontend-wiring section is for.

## Layout

```
core/
  models.py    Item — the one record shape every source produces
  store.py     SQLite + FTS5, dedupe, seen-URL tracking
  fetch.py     HTTP: robots.txt, per-domain rate limit, retries, thread-safe
  clean.py     HTML -> article text (trafilatura, no LLM)
  sources.py   keyword-searchable backends for sweeps
  sweep.py     fan out -> dedupe -> fetch -> rank -> roll up
  enrich.py    Claude scoring and summarisation
  report.py    terminal + markdown renderers, CLI progress formatting
  alerts.py    watchlist matching for scheduled mode
adapters/      scheduled-mode collectors: rss, gdelt, webpage, social.
               Stateful (they consult store.is_seen) and they never raise on an
               ordinary failure — a scheduled run is unattended, so one dead
               feed must not stop the others. The inverse of sources.py.
web/
  app.py       FastAPI, SSE streaming
  static/      index.html, style.css, app.js — no build step, no framework
```

The web layer serves both sides. Routes under `/api/scamscan/*` are the only
place the two meet, and they go through `scamscan`'s public functions
(`hunt`, `score_finding`, `db_connect`, `upsert`) rather than reaching into its
internals. `hunt()` takes a `progress(dict)` callback for exactly the same
reason `sweep()` does: the CLI renders the dicts as lines, `/api/scamscan/hunt`
forwards them as SSE frames, and neither owns the format.

`POST /api/investigations` is the graph-oriented workflow used by the Discover
view. Its free-first providers live under `watchtower/discovery/` and persist
through `investigation/storage.py`. Do not route it back through
`/api/discover`, which is the legacy DuckDuckGo classifier retained for API
compatibility. Provider observations become `Evidence`; derived correlations
must reference an evidence ID; optional model interpretation never creates an
observation. Direct social-platform crawling is intentionally absent.

Note the event vocabulary differs by design. A per-query failure is
`unsearched`, not `failed` — `failed` is the stream-level fatal event on both
sides, and a query that could not run is a normal, expected outcome that must
still be visible. Rendering those the same way is the bug the whole tool exists
to prevent.

scamscan is deliberately flat — one file, no package. It shares nothing with
`core/` and must not import from it:

```
scamscan.py       artifacts, impersonation, lexicon, scoring, store, CLI
config.json       brand, seed topics, lexicon, weights, search settings
scamscan_test.py  offline; no network, no API key
```

## Decisions that should not be reversed without a reason

These were each made deliberately. If you're about to change one, say so
explicitly rather than doing it as a side effect of something else.

**robots.txt is fetched through the shared httpx client, not
`urllib.robotparser.read()`.** urllib opens its own connection, ignores the
configured user agent and timeout, and treats a 403 on `/robots.txt` as
"disallow everything". Behind a corporate proxy that silently kills every fetch
in the app. This was a live bug; the fix is in `fetch.py::allowed`. Status
handling follows RFC 9309: 4xx allow, 5xx back off.

**API calls and crawling are separate activities, and only crawling obeys
robots.txt.** `Fetcher.get(url, api=True)` skips the robots check and is used
by every backend in `core/sources.py`; `api=False` (the default) keeps it and
governs article-body crawling in `sweep.py` and everything in `adapters/`.
robots.txt governs crawlers indexing pages — it is not the access-control
mechanism for a documented public JSON API you are calling as an intended
consumer. `en.wikipedia.org/robots.txt` disallows `/w/`, which is the path of
the API Wikipedia publishes for exactly this purpose and governs with its own
rate-limit and user-agent policy. Applying robots to both silently cost us
every Wikipedia and Google News hit. Do **not** "fix" a blocked source by
setting `obey_robots: false` globally — that removes the protection where it
actually belongs.

**A source that could not be searched never renders as zero.** Backends raise
`SourceError` (blocked, 429, timeout, unparseable body) or `SourceSkipped` (no
credentials) instead of returning `[]`. `sweep.py` sorts these into
`result.failed` and `result.skipped`, kept apart from a genuine zero in
`per_source`, and `SweepResult.complete` is false if either is non-empty. For
screening work this is the whole point: "no adverse media exists" and "we could
not look" must never render the same way, because a clean result that is really
a failed fetch is a false negative someone signs off on. If you add a backend,
raise — do not return `[]` on failure.

**Dedupe is on content hash of title+body, not URL.** One story syndicated to
five outlets under five URLs is one story.

**Claude is only in the scoring layer.** Not fetching, not parsing HTML where a
CSS selector works. Keep it that way — it's slower, costlier and
nondeterministic for those jobs.

**Ranking is two passes.** Free keyword scoring runs over everything; only
plausible candidates reach the model, capped by `--max-ai`. Removing the
prefilter makes every sweep cost real money.

**Cost controls in `enrich.py`:** system block marked for prompt caching (the
`focus` string goes in the user turn so the cached prefix stays identical),
Haiku triages and only items above `escalate_above` get a Sonnet pass, tool use
forces valid JSON. Models: `claude-haiku-4-5-20251001` and `claude-sonnet-5`.

**Two model providers, chosen by which key is set.** `available_provider()` in
`enrich.py` and `provider()` in `scamscan.py` both prefer **Gemini** when
`GEMINI_API_KEY` is present, because it has a free tier and a depleted Anthropic
balance is the common case here; `WATCHTOWER_LLM_PROVIDER` / `SCAMSCAN_PROVIDER`
(or `search.provider` in `config.json`) force one. Neither SDK is a hard import
— both are wrapped in `try/except ImportError`, so the tools still run with
either one absent.

What differs per provider is not the call but the **failure shape**, and that is
the part that must not be flattened:

- Anthropic forces JSON with a tool / `output_config.format`; Gemini uses
  `response_json_schema` + `response_mime_type`. Both end up with valid JSON, so
  nothing regex-parses prose on either path.
- **Anthropic reports a failed search as an error object inside a 200. Gemini
  just answers anyway, from the model's own memory, and the only evidence is
  negative — `grounding_metadata.web_search_queries` is empty.** An ungrounded
  answer to "search for scam pages" is a query that never ran, and it is the
  more dangerous of the two because the text comes back well formed.
  `grounding_failures()` is scamscan's Gemini-side `search_failures()`;
  `run_failures()` dispatches. Expansion passes `expected_search=False`, since
  it declares no tool.
- `stop_reason: refusal` ↔ `finish_reason` in `GEMINI_REFUSALS` or
  `prompt_feedback.block_reason`. `pause_turn` ↔ `finish_reason: MAX_TOKENS`.
- Free-tier Gemini is rate limited per minute and a sweep enriches up to
  `--max-ai` items back to back, so `_call_gemini` retries 429s with jittered
  backoff. Without it the tail of every sweep comes back unscored and reads as a
  run of irrelevant articles. A *daily* quota exhaustion is fatal and stops the
  run; a per-minute limit is not.

Model IDs are config values, not constants, because they move faster than this
file — `python scamscan.py models` lists what a key can actually reach.

**Scraped platforms stay absent; official APIs are fine.** Instagram, TikTok,
LinkedIn and Facebook have no usable public API, prohibit scraping, and fail
*silently* — a scraper returns an empty list and you believe you have coverage.
Do not add them, even if asked casually; raise the tradeoff first. The line is
the interface, not the brand: **X is included via its official paid API**
(`X_BEARER_TOKEN`), because a documented endpoint with a contract behind it
fails loudly. If TikTok Research API access is ever granted, the same reasoning
would admit it. Mastodon and Bluesky were evaluated but are retired from the
product defaults because unauthenticated search is inconsistent and adds
latency without dependable coverage. Brave web search is also retired from the
default path because it is metered; Common Crawl and DuckDuckGo remain the
free discovery fallback.

**ICIJ Offshore Leaks is intentionally not a backend.** It is the single most
on-topic dataset for beneficial ownership, and it publishes no API — the only
way in is scraping the search UI, which is the thing above. Their bulk data
download is the honest route if this is ever wanted.

**Everything degrades without keys — visibly.** No `ANTHROPIC_API_KEY` means
keyword ranking, not a crash. No `OPENSANCTIONS_API_KEY` means that backend
raises `SourceSkipped`, which the sweep records in `result.skipped` and the UI
renders as an "off" lane. It used to return `[]` silently; that was changed
deliberately, because an unsearched sanctions list reported as a clean one is
the most dangerous silent zero in the tool. The sweep still completes and
nothing crashes, so the tool stays testable and demoable without any key.

**Source diversity cap of 3 per domain** in `sweep.py::_diversify`. Without it,
wire copy fills the entire first page.

**Scores are adjusted after ranking, in `sweep.py::_adjust`,** for both keyword
and model scores. Three inputs the scorer itself cannot see:

- *Corroboration.* Dedupe collapses a syndicated story into one row; the number
  of distinct domains that carried it is kept in `raw_meta["corroboration"]`
  and adds up to +18. The model scores each item alone and cannot know five
  outlets ran it. Additive and capped on purpose — it should promote a
  well-attested story over an equally relevant single-sourced one, never
  rescue an irrelevant one.
- *Source tier* (`SOURCE_TIER`): watchlist > regulatory > dataset > news >
  reference > social. A regulator's circular and a content farm are not equally
  good evidence. A multiplier, so it breaks ties rather than inventing
  relevance.
- *Headline-only penalty.* An item with under 200 characters of body was never
  read, so it is capped at 55 and flagged in the UI. A matching headline means
  the words appeared, not that the piece is about your query.

## hunter

`hunter/` discovers candidate infrastructure itself (CT, typo generation, public search, pivots), enriches it
in stages, extracts signals, scores it, correlates it into campaigns, and raises rare alerts. It reuses
`investigation/` (graph store, additively extended) and `watchtower/discovery/` (safe fetcher, page parser)
and is **independent of scamscan**: it imports nothing from it and nothing imports it (a test enforces this).
`HUNTER.md` is the operator guide; `HUNTER_PLAN.md` holds the decisions and findings. The rules that must hold:

- **Unseen is not clean.** A page that was blocked, challenged, JS-only, unreachable or not fetched, or a name
  that does not resolve, scores as `UNASSESSED`, never `LOW`. A search that was blocked is never "no results"
  (DuckDuckGo needs a passing control query first). Missing RDAP is never a risk factor.
- **Every score is explainable and reproducible:** reason weights sum to the score; each reason cites evidence
  ids or a stated basis; `gather_inputs()` rebuilds a score from stored evidence only. No model in that path,
  and no weight changes by itself: only config edits, or an administrator approving a trusted classification.
- **Evidence is append-only.** Only the retention purge rewrites it, and it leaves an audit row.
- **GET only, no JavaScript, no credentials, no payments, no CAPTCHA handling.** Forms are parsed, never filled.
  One definition of a public address (`is_public_ip`) guards fetching, TLS and queueing.
- **Weak links never make a campaign** (registrar, CDN, a link to the same site). One strong link, or two
  independent medium links. Derived edges cite a correlation evidence row.
- **Recursion is bounded on every axis** and every skipped pivot is counted and logged on its parent.
- **Advisory pages are quoted indicators, not actors:** no pivots from them; negation, not "beware", demotes a
  phrase match, because an attacker can add the latter.
- Fixtures: vary certificates and nameservers per fake domain, or any two domains look linked by two medium links.

## Conventions

Adding a sweep source: one function in `core/sources.py` with signature
`(query, fetcher, hours, limit) -> list[Item]`, registered in `BACKENDS`. Nothing
else changes. If a source can't be mapped onto `Item`, that's a signal it needs
its own store rather than a hack to fit.

Progress reporting: `sweep()` calls `progress(dict)`. The CLI renders those via
`report.progress_line`; the web layer forwards them as SSE frames. Neither owns
the format — add a field, don't change existing ones.

Comments explain *why*, not what. Several in this codebase document a trap
(the robots.txt one, the `total_changes` inflation in `store.py::add`, the
relative bar scale in `app.js`). Don't strip them.

Frontend has no build step and no framework. Vanilla JS, `EventSource` for SSE,
CSS custom properties for tokens. Keep it that way — the whole point is that it
runs with `python run.py serve` and nothing else.

## UI design tokens

Defined in `web/static/style.css`. Cool paper ground, quiet everywhere, with
saturated colour reserved for the relevance ramp — if something is coloured, it
means something.

```
--paper #E7ECEF   --surface #FFFFFF  --sunk #DDE4E8
--ink   #0F1A22   --muted   #5C6B76  --faint #8A9AA5  --rule #C6D1D8
ramp: --weak #97A6B0  --low #46748F  --med #B5741A  --high #A82C22
type: IBM Plex Mono (display, labels, all numerics) + IBM Plex Sans (body)
```

Sweep timing: 30-60s without scoring. With it, one model call per candidate and
a free-tier Gemini key rate limited per minute means a 25-item pass can run
several minutes. That is why the trace exists and why `SWEEP_BUDGET` matters on
serverless.

Signature element is the sweep trace: source lanes that fill live as each
backend reports in. Don't replace it with a generic spinner — a sweep takes
30-60s and the lanes are what make a silent zero-hit source visible.

## Known gaps

- **GDELT rate-limits hard from a single IP**, which surfaces as a failed lane
  rather than a zero. Backing off across sweeps, or caching, is unsolved.
- **Retired social/web providers remain legacy adapters** for old explicit CLI
  jobs, but are hidden from defaults and the web source catalog. New workflows
  use indexed social links, Common Crawl and safe page inspection instead.

Verified in Chrome at 1440 / 820 / 380px on 2026-08-13: layout, the sweep
trace, all four relevance bands, sticky sidebar, keyboard focus rings,
`prefers-reduced-motion`, offline font fallback, empty/error/no-source states,
and that a finished sweep does not silently re-run.
- The hunter's crt.sh queries often 502 and DuckDuckGo soft-blocks bots; both are reported, not hidden (see `HUNTER.md`).
- No authentication on the web server. It binds to localhost. Anything beyond
  that needs a reverse proxy with auth first.
- `adapters/webpage.py` reads PDFs via `pypdf`, but a scanned circular has no
  extractable text. It records `extract_note` saying so rather than storing an
  empty body that would read as "nothing was published".
- The `webpage` entry in `config.yaml` is commented out — point it at a
  regulator you actually watch and check the `link_pattern` with
  `run.py collect` before trusting it.

## scamscan

`scamscan.py` + `config.json` + `scamscan_test.py`. Docs in `SCAMSCAN.md`.
Costs real money on every run (web search is billed separately from tokens, at
roughly $10 per 1,000 searches) — `--topics 1` first, always.

**The model proposes; local code decides.** Anything that drives analyst
workload is computed in auditable Python, never inside a prompt. Claude returns
candidate pages and a confidence; `score_finding` does the scoring. Keep it that
way — a score you cannot reproduce offline is a score you cannot defend.

**A query that never ran must never look like a query that found nothing.**
This inverts watchtower's bias: there, a zero is boring; here, an empty queue is
read as "this brand is clean", so a silent failure is a false negative someone
acts on. Three failure modes all return a successful HTTP 200 and would
otherwise parse to `[]`:

- **Web search errors** arrive as a `web_search_tool_result` block whose
  `content` is an error object rather than a list of results. Nothing raises.
  `search_failures()` detects them; `hunt_query` raises `HuntError`.
- **`stop_reason: "refusal"`** — these prompts describe fraud bait copy on
  purpose, so a safety decline is plausible. Checked before the response is
  parsed.
- **`stop_reason: "pause_turn"`** — the server-side tool loop hit its iteration
  cap. Results are real but partial, and the run says so.

`cmd_hunt` collects every failure and prints an `INCOMPLETE RUN` block. If you
add a code path that can return no findings, it goes through `HuntError` too.

**Absent ≠ zero in scoring.** `score_finding` averages only the families that
actually reported. Treating a missing `model_confidence` as `0.0` was a flat
25-point penalty that pushed genuine escalations under
`auto_escalate_threshold`. An explicit `0.0` still counts; an absent field is
excluded and recorded in `scored_on`.

**Dedupe keeps cross-site duplicates.** Same site + same copy collapses and
increments `times_seen`; the *same copy on a different site* stays separate on
purpose — cross-site reuse is the coordination signal, not noise.

**Page content is untrusted data.** The hunt prompt says so explicitly, and
scoring never executes anything from a page. If a page contains text addressed
to the model, that is reported as evidence, not followed. Never let extracted
content reach a shell, a SQL string, or a follow-up prompt as an instruction.

**Exports are personal data.** `queue.csv` and `*.csv` are gitignored. The
compliance section in `SCAMSCAN.md` is not boilerplate — confirm lawful basis,
retention, and access before running this against live traffic.

**The response shape is enforced by the API, not by prompt begging.** `hunt` and
`expand_queries` send `output_config.format` with a JSON schema
(`FINDINGS_SCHEMA`, `QUERIES_SCHEMA`). Under a schema a parse failure raises
`HuntError` — the API guarantees conforming JSON, so a failed parse is a broken
contract, and salvaging it would yield `[]`, which reads as a clean brand. The
docs do not say whether this composes with a *server-side* tool, so the run finds
out: `structured_rejected()` matches only a 400 naming `output_config`,
`json_schema` or `output format`, downgrades to `parse_payload(strict=False)` for
the rest of the run, and prints it twice — inline and in the closing summary.
Every other 400 propagates. Do not widen that matcher; a credit-balance 400
silently downgrading the run is precisely the failure this tool exists to catch.
`selftest --live` settles the question in two calls.

**The web search tool version is derived from the model, never hardcoded.**
`web_search_20260209` (dynamic filtering — Claude filters results in a sandbox
before they reach the context) only exists on the families in
`DYNAMIC_FILTERING_MODELS`. Elsewhere `web_search_tool()` returns
`web_search_20250305` and names the reason, so switching to a cheaper model
degrades instead of 400ing on every query.

**Lexicon terms carry provenance and match on word boundaries.** Entries are
`[weight, "SOURCE"]`; the source rides into `lexicon_hits` so a score can be
defended. `term_pattern` asserts `\b` only where the term's own edge is a word
character (`*locked*` has none) and turns internal spaces into `\s+`. Substring
matching was survivable with invented terms and is not with real ones — `otp`
inside "adoption", `reversal` inside "irreversible". `counter_terms` subtract
before the clamp, because an advisory quotes the bait verbatim and would
otherwise score like it. Bare-number entries still parse, so older configs work.

**Gemini's free tier does not include Google Search grounding** (verified live;
3.x is paid-only and the 2.5 models that had 500/day free now 404). Ungrounded
calls on the same key work, so watchtower scoring is fine and only scamscan's
`hunt` is blocked. `call_gemini` translates that specific 429 into a HuntError
naming the cause, because "rate limited" would send someone off to wait for a
quota that is never coming back. `hunt --dry-run` exists for this: expansion
uses no search tool, so it runs free, and it sets `complete: false` and writes
nothing so it can never read as a hunt that found nothing.

**Gemini 3 bills thinking against `max_output_tokens`.** A budget sized for the
output alone truncates the JSON mid-string — this broke expansion at 800 tokens
until `thinking_budget=0` was set there (thinking buys nothing for "write three
search queries"). `hunt` keeps thinking and takes 8000 instead. Anthropic counts
output only, so this is a Gemini-path concern.

Known gaps: the lexicon is Kenyan, so Tanzania and Lesotho are uncovered; the
Sheng bucket is thin and `UNVERIFIED` because published reporting quotes English
and Kiswahili; `ARTIFACT_PATTERNS` still substring-matches, so `pin_request`
fires on "never share your PIN".

## Deployment

Designed to run locally (`python run.py serve`, bound to 127.0.0.1). It is also
deployed to Vercel, which it does not naturally fit — three accommodations make
that work, and all three are visible to the user rather than silent:

- **Storage.** The deployment bundle is read-only, so `DATA_DIR` moves to
  `/tmp/watchtower` when `VERCEL` is set. `/tmp` does not survive between
  invocations, so the archive is ephemeral there. `/api/sources` returns
  `ephemeral_storage: true` and the UI prints a warning, because "Keep results"
  appearing to work and then losing the data is exactly the silent failure this
  codebase exists to avoid. Set `WATCHTOWER_DATA_DIR` to a real mounted volume
  to get persistence back.
- **Auth.** Off localhost the app **fails closed**: with no
  `WATCHTOWER_PASSWORD` set it serves 503 rather than exposing `/api/sweep`,
  which spends real money against `ANTHROPIC_API_KEY`. With one set it requires
  HTTP Basic, compared with `secrets.compare_digest`. Locally it stays
  passwordless, which is the documented design.
- **Time.** `sweep(budget=...)` bounds the wall clock; `SWEEP_BUDGET` defaults
  to 270s under `vercel.json`'s 300s `maxDuration`. Sources that don't finish
  are recorded in `result.skipped` as "exceeded the sweep time budget" — the
  same channel as a missing key, because it is the same fact: not searched.
  The executor is shut down with `wait=False`, otherwise `__exit__` blocks on
  the slowest backend and the budget is cosmetic.

Environment variables, in the host's settings and in `.env` locally (both
`run.py` and `scamscan.py` load `.env`; real environment variables win):

| Variable | Needed | What it does |
|---|---|---|
| `WATCHTOWER_PASSWORD` | **required off localhost** | Without it the app serves 503. HTTP Basic. |
| `GEMINI_API_KEY` | one of these two | Scoring, summaries, scamscan. Free tier covers scoring but **not** search grounding. |
| `ANTHROPIC_API_KEY` | one of these two | Same, plus scamscan's server-side search. |
| `WATCHTOWER_USER` | optional | Basic-auth user, default `watchtower`. |
| `OPENSANCTIONS_API_KEY` | optional | Otherwise that lane renders "off". |
| `WATCHTOWER_DATA_DIR` | optional | A mounted volume. Without it `/tmp`, and the archive **and the scamscan review queue** are ephemeral. |
| `WATCHTOWER_SWEEP_BUDGET` | optional | Wall-clock ceiling, default 270s. |
| `WATCHTOWER_LLM_PROVIDER`, `SCAMSCAN_PROVIDER` | optional | Force `gemini` or `anthropic`. |
| `GEMINI_TRIAGE_MODEL`, `GEMINI_DEEP_MODEL`, `SCAMSCAN_GEMINI_MODEL` | optional | Model overrides. |

On Vercel the review queue is the thing that suffers most from ephemeral
storage: a lost sweep can be re-run, a lost analyst verdict cannot. Set
`WATCHTOWER_DATA_DIR` to a mounted volume before using the Queue tab in
anger.

Scheduled mode cannot run on Vercel — it needs a persistent database, so it
belongs on the GitHub Actions schedule.

## Legal and ethical constraints

Not boilerplate — these shape the design.

- `obey_robots: true` stays on by default.
- Rate limiting is per domain, not global.
- `user_agent` in `config.yaml` should carry a real contact address.
- Social posts are personal data. Kenya's Data Protection Act 2019 requires a
  lawful basis, a stated purpose and a retention limit. `RETENTION_DAYS` in
  `adapters/social.py` is enforced on every scheduled run — don't remove the
  purge call.
- Sweeping a named private individual is a different activity from sweeping a
  topic or a company. If a request moves in that direction, flag it rather than
  just building it.

## Good next tasks

Task prompts live in `prompts/`. Start with `prompts/01-verify-ui.md`.

1. **Tune scoring against real results.** The pipeline is verified end to end
   on live data now, so this is the remaining quality lever — start with the
   scamscan lexicon (`Score` tab is free) and `enrich.py`'s scoring rubric.
2. **Rebuild the scamscan Sheng lexicon from your own confirmed cases.** It is
   the only bucket still marked `UNVERIFIED`.
3. CSV/JSON export from the web UI (scamscan has `export`; watchtower does not).
4. Saved queries that re-run on the GitHub Actions schedule.
5. GDELT back-off across runs — it still 429s from a single IP.
