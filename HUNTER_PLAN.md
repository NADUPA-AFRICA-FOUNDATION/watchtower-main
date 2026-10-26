# Autonomous Hunter — Milestone 1: audit and plan

Status of the repo on 2026-09-30 (branch `main`, 42 tests green). The spec calls the
product "Mnara"; in this repo it is the watchtower web UI (the UI is already branded
Mnara). No rewrite: the hunter is a new `hunter/` package that composes what exists.

## Stack found

- Python 3.9+ (CI: 3.10), FastAPI in `web/app.py`, vanilla JS/CSS front end, no build step.
- SQLite everywhere (`watchtower.db`, `scamscan.db`, investigation store). No ORM.
- CI: compileall, `flake8 --select=E9,F63,F7,F82`, `pytest`. No mypy in CI.
- Auth: none on localhost, HTTP Basic off localhost (fails closed). No per-analyst identity.
- Scheduler: none in-process. Scheduled mode is `run.py run` driven by GitHub Actions.
  Vercel deployment has ephemeral `/tmp` storage, so the hunter is a local/Actions/Railway
  feature, same as scheduled mode.

## Implementation map

| Spec area | State | Where / note |
|---|---|---|
| Entity, Evidence, Relationship models with stable IDs | EXISTING | `investigation/models.py`. Relationships already require `evidence_id`. |
| Normalization (domain, URL, phone, social) | PARTIAL | `investigation/normalization.py`. Missing: email, IP, crypto address, Telegram/WhatsApp as distinct types, Kenyan `07xx`/`254` equivalence tests. |
| Persistent schema (entities, evidence, relationships, campaigns, scores, verdicts, observations, source_runs) | EXISTING | `investigation/storage.py`, `migrations/002_investigation_graph.sql`. Append-only observations already. |
| Persistent candidate queue | MISSING | `investigation/queue.py` is an in-memory heap. Needs `hunt_jobs` table with status/attempts/depth/parent. |
| Dedup with first_seen/last_seen/sources_seen/count | PARTIAL | `entities` has first/last seen only. Needs observation count and sources_seen. |
| Provider architecture | EXISTING | `watchtower/discovery/base.py` (`DiscoveryProvider`, `SourceHealth`, `ProviderRun`), orchestrator isolates failures. |
| CT discovery | EXISTING | `CertificateTransparencyProvider`. Needs brand-config driven terms and incremental "since" cursor. |
| DNS, RDAP, TLS enrichment | EXISTING | `DNSProvider`, `RDAPProvider`, `TLSProvider`. Check MX/NS/TXT coverage. |
| Public search discovery | EXISTING | `DuckDuckGoProvider`, `CommonCrawlProvider`. Needs phrase templates. |
| Typo/permutation generator | MISSING | Not present. Must be bounded and prioritised. |
| SSRF-safe fetch (DNS pinning, redirect revalidation, size cap) | EXISTING | `watchtower/discovery/safe_fetch.py`. Reuse as-is; no new fetch path. |
| Page parsing (title, links, forms) | PARTIAL | `page_analysis.py`. Needs form *field types*, wa.me/t.me extraction, paybill/till, crypto, visible-text phrases. |
| Content acquisition abstraction (Firecrawl-ready) | MISSING | Add `ContentAcquisitionProvider` with `NativeFetcher` wrapping `SafeFetcher`. No Firecrawl dependency. |
| Deterministic explainable scorer | PARTIAL | `watchtower/discovery/scoring.py::score_domain` returns `EvidenceScore`. Spec weights (incl. negative official/trusted) and config-editable weights need adding. |
| Official / trusted domain lists | PARTIAL | `core/trust_filter.py`, `core/trusted_domains.py` (hardcoded). Needs per-brand `official_domains` in config. |
| Correlation / campaign clustering | PARTIAL | `investigation/correlation.py` (`clusters`, `correlation_score`). Needs strong/medium/weak link classes and shared-infra denylist (Cloudflare, AWS…). |
| Recursive pivots with limits | PARTIAL | `Budgets` has depth/entity caps. Missing per-entity pivot cap, per-campaign cap, daily budget, pivot priority table. |
| Analyst disposition | PARTIAL | `analyst_verdicts` + `POST /api/entities/{id}/verdict`. Verdict vocabulary differs from spec; needs mapping, not a second table. |
| Score history / rescoring | PARTIAL | `scores` table is append-only. No rescoring trigger. |
| Change detection | MISSING | Observations exist; no diff step. |
| Provider health persistence | PARTIAL | `source_runs` per investigation. No rolling last-success/latency/circuit state. |
| Market detection | MISSING | Not present. |
| Scheduler | MISSING | Add a single-process loop (`python run.py hunt`) plus an Actions cron entry. No new infra. |
| Alerting with dedupe | PARTIAL | `core/alerts.py` is watchlist matching only. |
| `/hunter/*` API | MISSING | Existing `/api/investigations/*` stays untouched. Use `/api/hunter/*` to match the current prefix. |
| Autonomous Hunting UI | MISSING | New view in `web/static`. |
| Legacy overlap | NEEDS REFACTORING | `osint_discovery.py`, `watchtower_async.py` (aiohttp, own CT/search code, and `_safe_get` without pinning) duplicate providers. Do not extend; leave and do not call from the hunter. |
| `campaigns/`, `hunters/`, `detection/` | EMPTY | Only `__init__.py`. `hunters/` name is too close to `hunter/`; leave alone. |

## Decisions and conflicts with CLAUDE.md

1. **Engine boundary.** The hunter lives with the watchtower side and the `investigation/`
   graph. It must not import `scamscan`, and `scamscan.py` must not import it. The
   scamscan lexicon is not reused; hunter phrases are their own config.
2. **A source that could not run never renders as zero.** Hunter providers raise or return
   `ProviderRun` with a failed/unavailable status; the health table and dashboard show
   it. Same rule as `SourceError` / `SourceSkipped`.
3. **Robots.** Provider API calls are API use; fetching candidate pages is crawling and
   goes through `SafeFetcher`. Whether `SafeFetcher` honours robots.txt is open (below).
4. **Retired sources stay retired.** No Instagram/TikTok/LinkedIn/Facebook scraping;
   X, Reddit, Bluesky, Mastodon appear in coverage only as `unavailable`/`off`.
5. **Untrusted content.** Page text is data. Nothing extracted reaches a shell, SQL
   string, or prompt as an instruction. AI, if used at all, only writes a summary and
   never sets score or status.
6. **Personal data.** Phone numbers, emails and handles extracted from scam pages are
   personal data under the Kenya DPA 2019. Add a retention setting and purge step
   (as `RETENTION_DAYS` does for social) before scheduled hunting is enabled.
7. **Schema.** Extend with new `CREATE TABLE IF NOT EXISTS` in a `003_hunter.sql` and
   the same idempotent runtime DDL. Do not alter existing tables destructively.

## Proposed layout

```
hunter/
  config.py        brands, official domains, weights, budgets (YAML, no secrets)
  normalize.py     indicator normalization (extends investigation.normalization)
  store.py         hunt_jobs, indicators/observations extensions, provider_health,
                   score history, dispositions view over analyst_verdicts
  queue.py         persistent queue: claim, retry/backoff, defer with reason
  permute.py       bounded permutation generator + cheap pre-score
  acquire.py       ContentAcquisitionProvider, NativeFetcher (wraps SafeFetcher)
  signals.py       page signal extraction (forms, CTAs, payments, phrases)
  scoring.py       weighted, config-driven, returns reasons + evidence ids
  pivots.py        pivot priority, depth/pivot/campaign/daily budgets
  campaigns.py     link-strength classes, shared-infra denylist, clustering
  market.py        market detection with confidence
  runner.py        stage pipeline, provider isolation, scheduler loop
web/hunter_routes.py   /api/hunter/* (included by web/app.py)
tests/test_hunter_*.py
```

## Milestones

1. Audit and plan (this file).
2. Indicator normalization + persistent queue + dedup counters.
3. CT discovery driven by brand config, plus permutation generator.
4. DNS/RDAP/TLS staged enrichment and provider health.
5. Native page acquisition behind `ContentAcquisitionProvider`.
6. Signal extraction. 7. Scorer with reasons. 8. Pivot engine with budgets.
9. Graph and campaign clustering. 10. Scheduler. 11. API and dashboard.
12. Security tests, docs, end-to-end scenario on `.test` fixtures.

Each milestone ends with pytest, the CI flake8 selection, and the four legacy suites green.

## Decisions on the open questions

1. **robots.txt: split by activity, always record the verdict.**
   - The single landing-page GET of a candidate URL is a targeted inspection, like opening
     a link or what urlscan and Safe Browsing do. It does not obey robots.txt
     (`hunter.obey_robots_landing: false`). The attacker controls that file, and obeying it
     would let a phishing site opt out of being looked at.
   - Anything beyond that page (`map_domain`, extra pages up to `max_pages_per_domain`,
     link following) is crawling and obeys robots.txt, as CLAUDE.md requires.
   - The robots verdict (allow, disallow, unreachable) is stored as evidence on every
     candidate. It is never scored, since it says nothing about intent.
   - This narrows one CLAUDE.md rule on purpose. It stays a config flag: set it to `true`
     and the hunter obeys robots.txt everywhere.
2. **Deployment: one long-running process on a persistent disk.**
   - Runs as `python run.py hunt`, locally or on Railway with `WATCHTOWER_DATA_DIR` on a
     mounted volume. The repo already ships `Dockerfile` and `railway.json`.
   - Not on Vercel (ephemeral `/tmp`) and not on GitHub Actions (no persistent SQLite between
     runs). The scheduler refuses to start when `VERCEL` is set or the data dir is
     ephemeral, and says why. A queue that silently resets is a silent failure.
3. **Analyst identity: authenticated when possible, labelled when not.**
   - Dispositions record the HTTP Basic username when auth is on. That value comes from
     the server, not the client.
   - On localhost without auth, a free-text analyst name is required and stored with
     `identity_source = "self_asserted"`, so a later reader can tell the two apart.
   - Dispositions are append-only, each with the previous verdict, reason and timestamp.
     Optional per-analyst credentials (`WATCHTOWER_USERS`) can come later without a schema change.

## Progress

- **M1 audit and plan:** done.
- **M2 normalization, persistent queue, dedup:** done (`hunter/normalize.py`, `hunter/store.py`).
- **M3 CT discovery, permutations, pre-score:** done. `hunter.yaml`, `hunter/config.py`,
  `hunter/prescore.py`, `hunter/permute.py`, `hunter/ratelimit.py`, `hunter/ingest.py`,
  `hunter/providers/{base,ct,permutation}.py`, `python -m hunter <cmd>`.

## Findings worth acting on

1. **crt.sh is unreliable for common terms.** A live run returned HTTP 502 for five of six
   wildcard queries (`%mpesa%` and similar time out server-side). The hunter reports this as
   `partial`/`provider_error`, keeps the cursor back and exits non-zero, so nothing is lost or
   shown as clean, but coverage from CT is poor until a second source exists. Options, in order:
   a Certstream provider (free live feed, push not poll), or crt.sh's public Postgres replica
   with a time-bounded query. Both fit `HuntProvider` without other changes.
2. **`watchtower/discovery/scoring.py` imports `scamscan.impersonation_score`.** That is a
   watchtower-side module reaching into scamscan, which the "dependency runs one way" rule in
   CLAUDE.md is meant to prevent. The hunter does not use it and has its own matcher. Untouched
   here; worth a separate change.
3. **Permutation candidates mostly will not exist.** They are stored with low confidence and
   submitted once per config. Milestone 4's DNS step must treat NXDOMAIN as "not registered
   yet, re-check later" (a slow re-resolve schedule), not as a permanent ignore.
4. **CT row cap.** If a term returns more than `max_rows_per_term` new rows in one poll, the
   oldest are dropped and the run says so. Poll often enough that this stays rare.

- **M4 staged enrichment:** done. `hunter/enrich/{dns,rdap,tls,pipeline}.py`, `python -m hunter enrich`.
  Light pass = DNS + RDAP then re-score; deep pass (MX/TXT + live TLS) only for FULL/HIGH re-scores,
  capped at `max_deep_per_hour`. Facts land in the graph store as evidence.

### M4 findings

1. **The pre-existing DNS provider hid failures.** `DNSProvider._lookup` swallows every exception per
   record type, so NXDOMAIN, SERVFAIL and a timeout all read as "no records". The hunter has its own
   resolver wrapper that keeps them apart. The old provider is untouched.
2. **The pre-existing TLS provider can probe internal hosts.** `TLSProvider` calls
   `socket.create_connection((domain, 443))`, which resolves inside the connect, so a candidate that
   resolves to 127.0.0.1 or a metadata address is contacted. It is used by the investigation engine
   (`/api/investigations`). Not changed here; worth fixing by routing it through `resolve_public`.
3. **Documentation IP ranges count as private.** Python treats 203.0.113.0/24 as private, so fixtures
   for the end-to-end scenario should use public-looking addresses or inject the resolver.
4. **RDAP is one lookup per registrable domain, no PSL.** Two-part suffixes outside the list in
   `hunter/config.py::TWO_PART_SUFFIXES` would query the wrong name. Shared-hosting subdomains skip
   RDAP (the registration is the platform's).
5. **New dependency:** `cryptography>=42` added to requirements.txt (it was already installed
   transitively; the hunter now imports it directly).
6. **Live check (scratch db):** 12 generated `.xyz` names -> DNS NXDOMAIN, CentralNic RDAP 404 ->
   deferred 1 day with the reason; all evidence stored. RDAP averaged ~4s per lookup because the
   per-registry limiter spaces requests 1s apart.

- **M5 page acquisition:** done. `hunter/acquire.py` (`ContentAcquisitionProvider`, `NativeFetcher`),
  wired into the deep stage; `python -m hunter fetch DOMAIN` captures one site by hand.
  GET only; robots split per the decision above (landing recorded not enforced, extra pages always
  enforced, 5xx/unreachable robots stops crawling beyond the landing page); no JS execution, flagged
  `js_shell_suspected`; meta-refresh targets recorded as `redirects_to` (confidence 0.6), not followed;
  snapshots are visible text only (capped), form fields are names/types never values.

### M5 findings

1. **Bug in M4 caught and fixed:** the deep stage queried only MX/TXT, so `lookup_domain` had no
   address types to judge and returned `status="error"` for every deep job, which also counted as a DNS
   failure in provider stats. Deep now re-queries A/AAAA/CNAME too (page capture should act on current
   answers), and a pass with no address types reports `ok`.
2. **Shared class touched:** `SafeFetcher` gained a `keep_headers` argument (default unchanged) so the
   hunter can keep `x-powered-by`/`x-generator` for technology fingerprints. Cookies are not kept.
3. **Existing page parser reused as is:** `analyze_page` supplies title, text, links and forms. Its
   `credential_fields` is a loose substring match; Milestone 6 builds the proper form classification.
4. **Page text is personal data risk.** Snapshots can contain phone numbers and emails. They carry
   `personal_data: true` in evidence metadata so the retention purge (still to build, before
   scheduling is enabled) can find them.
5. **No JavaScript rendering exists in the repo**, so SPA-only phishing pages are seen as empty shells.
   They are flagged, not scored clean. A headless-browser provider would implement the same interface.

- **M6 signal extraction + market detection:** done. `hunter/signals.py`, `hunter/market.py`, wired
  into the deep stage after page capture; `python -m hunter fetch DOMAIN --signals` shows what is found.
  Per page: one `page_signals` evidence (flags + indicators + forms + phrases, the thing the scorer
  cites) and one `extracted_indicator` evidence per indicator with `where`, snippet, confidence and
  `pivot_value`. Relationships: uses_phone/whatsapp/telegram/email/payment_identifier/crypto_wallet/
  social_account/analytics_id, links_to. Market goes to `hunt_candidates.market` plus a
  `market_estimate` evidence.

### M6 findings

1. **A page we could not see must not read as clean.** Live check against safaricom.co.ke: HTTP 403
   from an Incapsula challenge. The fetcher used to treat it as a normal page and follow links inside
   the challenge. Now `Page.unassessed_reason` (HTTP block, bot challenge, JS-only shell) is recorded,
   surfaces as the `content_unassessed` flag, and extra pages are only crawled past a real 2xx.
   Nothing tries to get past a challenge. **Milestone 7 must score `content_unassessed` as unknown,
   never as low risk.**
2. **Advisory handling is deliberately asymmetric.** A phrase match is demoted locally only by
   negation ("never", "do not", "not to"). Softer words ("beware", "warning") demote only at page
   level, and only when the page has no credential form, because those words are free for an attacker
   to add. "Security alert"/"warning" in a title do not count as advisory (phishing pages use them).
   Result: a news article quoting the lures yields no solicitation, a phishing page with "Beware of
   scams" and a PIN box still does.
3. **Security reports list IOCs as live-looking text.** They are extracted (as sightings) but the
   page carries `advisory_context`. **Milestone 8's pivot rules must not pivot from advisory pages**,
   or the hunter will chase the infrastructure of a report instead of the actor.
4. **Account numbers are not extracted, and the snippet is tight.** A Paybill's account number can be
   a person's phone; only the Paybill/Till identifier is kept, and its snippet is the matched span only.
   (A test caught the snippet window leaking it.)
5. **Correlation note for Milestone 9:** a WhatsApp number is emitted as both `whatsapp` and (when
   found in text) `phone_number`; wa.me links give `whatsapp` only. The correlator must treat the same
   E.164 across those types as one identity.
6. **Not done:** favicon hash (needs one more fetch per site) and Kiswahili/Sheng lexicon review by a
   native speaker; the Kiswahili rules are standard Kiswahili and marked as such in the code.

- **M7 transparent risk scoring:** done. `hunter/scoring.py`, `hunt_scores` history table,
  `scoring:` section in `hunter.yaml`, `python -m hunter explain DOMAIN` and `rescore [DOMAIN|--all]`.
  Light and deep passes now end `SCORED` (or `ESCALATED` at `scoring.escalate_at`); previously `ENRICHED`.

### M7 design and findings

1. **Reproducible by construction.** `score()` is a pure function; `gather_inputs()` rebuilds its inputs
   from stored evidence only. A test re-derives a stored score offline and compares content hashes. Each
   history row stores the config hash, so a weight edit is attributable.
2. **Explainability invariant (tested on every scenario):** reason weights, including the cap/clamp rows,
   sum to the score exactly; every reason either cites evidence ids that exist in the graph store or names
   a non-evidence basis (`domain_name`, `config`, `adjustment`).
3. **Unseen is not clean.** A low score with an unseen page (blocked, challenged, JS-only, unreachable,
   not fetched) or a name that does not resolve is classified `UNASSESSED`, a fifth class beyond the
   brief's four, unless the domain is official/trusted by configuration. Missing RDAP is never a factor.
   Consequence to expect: weak candidates stop after the light pass (staging saves cost), so they sit as
   `UNASSESSED / page not fetched` until something justifies a deep pass. That is the honest label.
4. **Brief's weights are the defaults**, plus additions marked `(+)` in `hunter/config.py` (card/ID
   fields, cross-origin form, credential/urgency/reward language, brand-off-official, advisory discount).
   A sign error in config (a discount that adds risk) is a load error.
5. **Brand relevance cap.** With nothing tying a page to the brand, the score is capped (default 40) by an
   explicit negative reason, so generic phishing of another brand surfaces as WATCH, not HIGH.
6. **Advisory pages:** quoted IOCs no longer raise the WhatsApp/payment/crypto flags when a page is an
   advisory that asks for no credentials (signals now sets `quoting_advisory`); advisory pages get a
   -15 discount.
7. **Known-bad reuse** reads analyst verdicts: another domain sharing a strong node (phone/WhatsApp/
   Telegram/payment/crypto/analytics) with a `confirmed_*` verdict adds +25 with cited evidence. A number
   is one identity whether found as `phone_number` or `whatsapp`. Nodes used by more than
   `shared_node_max_domains` domains are treated as generic. **Gap for Milestone 11:** the graph store's
   verdict vocabulary (`InvestigationStore.VERDICTS`) does not include the brief's `CONFIRMED_SCAM`,
   `CONFIRMED_IMPERSONATION`, `FALSE_POSITIVE`; it must be extended there, and a disposition must trigger
   `rescore(..., trigger="analyst_verdict")` on its neighbours.
8. **Trust discount is never given to shared-hosting subdomains** (`x.vercel.app`), even if the platform is
   listed, since an attacker can sign up for one. The bundled trusted list also contains social platforms,
   which is harmless for domain candidates but must not be applied to URL-level scoring.
9. **Still to do for scoring:** analyst-disposition feedback (Phase 17) and threat-feed evidence
   (`threat_feed_hit` is read when present but nothing writes it yet).

- **M8 recursive pivots:** done. `hunter/pivots.py`, `hunter/search.py`; `pivots:` section in `hunter.yaml`.
  Indicators found on a page become depth+1 candidates (parent and the sighting's evidence id recorded);
  claimed indicator candidates are looked up in the local graph, then searched publicly.
  Bounds, all configurable and all logged on the parent (`pivots` / `pivot_suppressed` events): max depth,
  per-entity, per-lineage (campaign, else originating candidate), per-day pivots, per-day searches,
  search rate limit, and a batch time budget. A test drives an endless A->B->C->... world and proves the chain
  stops at exactly `max_depth + 1` domains.
- **M9 graph and campaigns:** done. `hunter/correlate.py`, `hunter/graphq.py`; `correlation:` section;
  `python -m hunter campaigns [ID]`, `correlate`, `lineage`.

### M8 and M9 findings

1. **DuckDuckGo "no results" is not trustworthy from a bot.** A live check showed a 200 "No results found"
   page for a query that has results, then HTTP 202 on the next one. `DuckDuckGoHtml` therefore believes
   `no_results` only after a quoted control query that must have results has just succeeded (cached 15 min);
   otherwise the answer becomes `blocked` and the candidate is deferred, never completed as a clean zero.
   An unparseable page is `error`, never `no_results`. The older `DuckDuckGoProvider` in
   `watchtower/discovery` and `osint_discovery.search_duckduckgo` have the same weakness (their own comment
   admits an empty answer is "commonly a transient backend block") and were left untouched.
2. **Pivot suppression rules:** no pivots from advisory pages, a site's own-domain email, invite/group codes,
   CDN/cloud/search/social hosts, official domains; generic outbound links are stored (status NEW) but not
   queued unless `queue_low`. Medium pivots (email, social, iframe/payment-style links) are queued by default.
3. **Lineage gates the deep pass.** A weak-looking name reached from a candidate scored >= 56 earns a deep
   pass; the same name found cold does not. Search hits are leads (confidence 0.3), never evidence: a hit
   joins a campaign only once its own page is seen to carry the shared indicator.
4. **Campaign rule:** a pair joins a campaign through one strong link, or two independent medium links.
   Weak links (registrar, CDN IP, mass-market nameserver, a link to the same site) are listed as detail and
   merge nothing. A node's weight decays above 5 users and is ignored above 20. A number is one identity
   whether found as phone or WhatsApp. The credential collector two sites post to is itself a member
   (strong `shares_form_endpoint`), by design.
5. **Every derived edge cites evidence.** `shares_*` and `member_of_campaign` relationships reference a
   `correlation` / `campaign_membership` evidence row naming the shared node and the sightings it rests on.
   Campaigns only grow or merge (oldest survives); splitting one is an analyst call. Every change is appended
   to `hunt_campaign_events`.
6. **Scoring loop guard.** `linked_suspicious_infrastructure` (+10) uses the neighbour's *own* score (its
   score minus this same factor), and neighbours are rescored only after the candidate's own score is
   recorded; a test shows repeated rescoring is stable.
7. **Test-fixture trap worth remembering:** if every fake domain gets the same certificate and nameservers,
   any two deeply-processed domains look linked by two medium links. Fixtures now vary both per domain.
8. **Not done / known limits:** reverse-IP is optional and disabled by default (free tier is ~50 lookups/day);
   favicon hashing is still absent; campaign splitting is manual; no mutual-TLS or WHOIS-registrant
   correlation (registrant data is mostly redacted, and kept only when visible).

- **M10 scheduler, alerts, change detection, retention, coverage, search discovery:** done. `hunter/scheduler.py`,
  `alerts.py`, `changes.py`, `retention.py`, `coverage.py`, `providers/search_discovery.py`, `runner.py`;
  `python run.py hunt [--once]`. Live one-pass run on a fresh store: CT `degraded` (3 of 6 terms answered, rest
  HTTP 502), permutation healthy, search discovery `failing` (DuckDuckGo HTTP 202), enrichment of 100 generated
  names all "not registered", every job completed.
- **M11 API, dashboard, dispositions:** done. `web/hunter_routes.py` (`/api/hunter/*`), `web/static/hunter.{js,css}`,
  `hunter/dispositions.py`. Verified in headless Chrome against a database seeded through the real pipeline.
- **M12 hardening, end-to-end, docs:** done. `tests/test_hunter_end_to_end.py`, `tests/test_hunter_security.py`,
  `HUNTER.md`.

### M10-M12 findings

1. **Real bug fixed in shared code:** `safe_fetch._public_ip` treated `100.64.0.0/10` (carrier-grade NAT, which
   contains Alibaba Cloud's metadata endpoint `100.100.100.200`), `192.0.0.0/24` and 6to4/Teredo/NAT64 addresses as
   public. One stricter `is_public_ip` now guards fetching, TLS and queueing everywhere (it requires
   `is_global` and excludes tunnelling ranges). This also tightens the pre-existing investigation engine.
2. **`next_due()` returned "now at call time"** for a never-run job, so with a real clock no job ever looked due
   (fake clocks hid it). Fixed by passing the caller's timestamp. Coverage also looked up `certificate_transparency`
   on the config instead of `ct`. Both were found by tests, not in production.
3. **Disposition effects are deterministic and narrow.** Confirmations rescore related domains and feed
   `known_malicious_infrastructure`; clearing keeps the record, slows refresh, silences score alerts (new evidence
   can still alert). Patterns from confirmed cases and classes of false positives are surfaced only with at least
   `insight_min_support` cases and change nothing until an administrator approves a trusted domain, which is logged,
   attributed and rescored under a new config hash.
4. **Auth reality:** the app has one shared Basic account, so "authenticated" dispositions record that account;
   per-analyst identity needs per-analyst accounts (not built). Without auth the typed name is stored as
   `self_asserted`.
5. **A listening server from another session** was found on port 8765 (`/tmp/mnara-venv`); it was left alone and
   the verification server used a different port.
6. **mypy:** the hunter package is clean (`python -m mypy hunter --ignore-missing-imports`); nine errors remain in
   older files (`scamscan.py`, `osint_discovery.py`, `watchtower/discovery/providers.py`) and were not touched.
