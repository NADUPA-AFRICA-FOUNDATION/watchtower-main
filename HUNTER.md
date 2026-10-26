# Autonomous hunter

Mnara finds suspicious infrastructure on its own, explains why it matters, connects related infrastructure,
keeps the evidence, and surfaces the few findings that deserve a person. You do not paste a domain in.

This is the operator's guide. `HUNTER_PLAN.md` holds the design decisions and the findings made while
building it; read that before changing anything here.

## Run it

```bash
pip install -r requirements.txt

python run.py hunt                  # the scheduler: runs until Ctrl-C
python run.py hunt --once           # every job once, then exit (cron, demos, first run)
python run.py serve                 # dashboard: the "Hunt" workspace (Hunting feed, Campaigns, Operations)
```

The hunter keeps its data in `hunter.db` under `WATCHTOWER_DATA_DIR` (default: the repo root, the same place the dashboard reads).
It **refuses to start** on storage that will not survive (a serverless `/tmp`): a queue that silently
resets is a silent failure. Set `WATCHTOWER_DATA_DIR` to a persistent volume, or
`WATCHTOWER_ALLOW_EPHEMERAL=1` for a throwaway demo. It cannot run on Vercel.

Inspect and operate it by hand (all read from the same database):

```bash
python -m hunter coverage            # which sources are healthy / degraded / rate limited / circuit-open / unsupported
python -m hunter status              # queue counts and provider health (JSON)
python -m hunter explain DOMAIN      # score, every reason with its evidence, score history
python -m hunter lineage DOMAIN      # how the hunter came to look at it
python -m hunter campaigns [ID]      # campaigns; with an ID: members, infrastructure, why related
python -m hunter alerts [--evaluate] # alerts
python -m hunter changes DOMAIN      # meaningful changes noticed over time
python -m hunter rescore [DOMAIN|--all]   # recompute from stored evidence, no network (after editing weights)
python -m hunter correlate           # rebuild campaigns from the whole graph
python -m hunter purge [--dry-run]   # apply the personal-data retention limit
python -m hunter brands | permute | score DOMAIN | fetch DOMAIN --signals | discover ct|permutation | enrich
```

Everything is configured in `hunter.yaml` (its own file: the hunter shares no config with watchtower or
scamscan). Unknown keys, a sign that is the wrong way round on a weight, and a config with no brands are load
errors, not silently ignored.

## Turning sources on and off

| Source | How | Default |
|---|---|---|
| Certificate Transparency | `certificate_transparency.enabled` | on |
| Typo / permutation generator | `permutations.enabled` | on |
| Public-search discovery | `search_discovery.enabled` (also needs `pivots.search`) | on |
| Indicator search (pivots) | `pivots.search` | on |
| Reverse-IP (HackerTarget, ~50/day free) | `pivots.reverse_ip` | **off** |
| DNS, RDAP, TLS, page capture | always part of enrichment; page capture is skipped if no acquirer is wired | on |
| Alert webhook | set the env var named by `alerts.webhook_env` | off (local only) |

A disabled source shows as `disabled` in the coverage report, never as healthy. Sources the hunter does
not support (X, Reddit, Bluesky, Mastodon, TikTok, Instagram, Facebook, LinkedIn, threat-intel feeds) are
listed as `unavailable` with the reason. Direct social-platform crawling is intentionally absent.

Environment variables (all optional; nothing paid is required):

| Variable | Purpose |
|---|---|
| `WATCHTOWER_DATA_DIR` | where `hunter.db` lives; must be persistent for the scheduler |
| `WATCHTOWER_CONTACT`, `WATCHTOWER_USER_AGENT` | identifies the hunter to the sites and registries it contacts |
| `WATCHTOWER_ALERT_WEBHOOK` | an https URL for outbound alerts (domain, score, signal names; no personal data) |
| `WATCHTOWER_ALLOW_EPHEMERAL` | `1` to run on `/tmp`-style storage anyway (demos, tests) |
| `WATCHTOWER_USER` / `WATCHTOWER_PASSWORD` | existing web auth; the hunter API sits behind it |

## Architecture

```
                         hunter.yaml  (brands, official domains, weights, budgets)
                              |
   +---------------------- SCHEDULER (one process, per-job interval, timeout, circuit breaker) ----------------------+
   |  certificate_transparency   permutation   search_discovery        enrich (continuous)   refresh   alerts   purge |
   +-----------+------------------+--------------+-------------------------+-------------------------------------------+
               |                  |              |                         |
               v                  v              v                         v
        +--------------- DISCOVERY PROVIDERS (isolated: timeout, retry, rate limit, health) -------------+
        |  crt.sh (cursor per term)   generated typos (bounded, ranked)   public search (soft-block safe)  |
        +-----------------------------------------+------------------------------------------------------+
                                                  | normalize -> dedupe -> pre-score (0-100: STORE/LIGHT/FULL/HIGH)
                                                  v
                     PERSISTENT QUEUE  hunt_candidates / observations / history   (SQLite, WAL, claim = BEGIN IMMEDIATE)
                                                  |
                    LIGHT PASS: DNS (A/AAAA/CNAME/NS) + RDAP  ->  re-score  -> not resolving? slow re-check, then ignore
                                                  |  strong, or reached from a suspicious candidate (lineage)
                                                  v
                    DEEP PASS: DNS (MX/TXT) + TLS (pinned) + page capture (SafeFetcher, GET only, robots split)
                                                  |
                      SIGNALS: forms by field type, WhatsApp/Telegram, Paybill/Till, wallets, phrases, market
                                                  |
        +-------------------+---------------------+---------------------+----------------------+
        v                   v                     v                     v                      v
   EVIDENCE (graph)    RISK SCORE            PIVOTS (bounded)      CORRELATION           CHANGE DETECTION
   append-only,        deterministic,        depth / per-entity /  strong/medium/weak    parked -> login page,
   immutable rows      reasons + evidence    lineage / daily /     links, campaigns,     IP moves, redirects
                       ids, history          search budgets        cited evidence
        \                   |                     |                     |                      /
         +------------------+----------+----------+---------------------+---------------------+
                                       v
                      ALERTS (rare, deduped)      API /api/hunter/*      DASHBOARD  (Hunting feed, Campaigns, Operations)
                                       |
                              ANALYST DISPOSITIONS  --(deterministic effects only)-->  rescoring, alert suppression, refresh rate
```

Code map: `hunter/` (engine), `hunter/enrich/` (DNS, RDAP, TLS, pipeline), `hunter/providers/` (CT,
permutation, search discovery), `web/hunter_routes.py` (API), `web/static/hunter.{js,css}` (UI). The graph and
verdict tables are the existing `investigation/` store, extended additively.

## Methodology

**Scoring** is deterministic and explainable (`hunter/scoring.py`). Every reason carries a weight and either
evidence ids from the graph store or a stated non-evidence basis (domain name, config); reason weights,
including the cap and clamp rows, sum to the score exactly, and a score can be recomputed offline from stored
evidence. There is no model in the path. Weights live in `hunter.yaml` and nothing adjusts them automatically;
each stored score records the config hash it was computed under.

| Brief's weights (defaults) | |
|---|---|
| brand in domain +15, brand typo +15, recently registered +10, login form +10, PIN field +20, OTP field +20 | |
| WhatsApp CTA +8, Telegram CTA +8, payment instruction +12, fee language +12, guaranteed returns +12 | |
| unrelated external payment domain +10, multiple signals +10, known malicious infrastructure +25 | |
| official domain -50, trusted third party -30, established organization -25 | |

Added beyond the brief and marked `(+)` in `hunter/config.py`: card and ID fields, a form posting to another
site, credential/urgency/reward language, brand named off an official domain, linked suspicious infrastructure,
and an advisory-page discount. Bands: 0-30 LOW, 31-55 WATCH, 56-75 SUSPICIOUS, 76-100 HIGH_PRIORITY.

A fifth class, **UNASSESSED**, exists because *unseen is not clean*: a low score with a page that was blocked,
challenged, JavaScript-only, unreachable or never fetched (or a name that does not resolve) is reported as not
assessed. Missing RDAP data is never a risk factor. With nothing tying a page to the brand, the score is capped
(default 40) by an explicit negative reason.

**Pivot rules.** Phones, WhatsApp numbers, Telegram handles, payment identifiers, wallets, analytics ids and
credential-collection or redirect domains are high value and queued; email, social profiles and iframe or
payment-style links are medium and queued; generic outbound links are stored but not queued. Never pivoted
from: advisory pages, a site's own email, invite/group codes, CDN/cloud/search/social hosts, official domains.
A search hit is a lead (confidence 0.3), never evidence.

**Recursion controls**, each configurable and each skip counted and logged on the parent: `max_depth` (3),
`max_pivots_per_entity` (10), `max_jobs_per_lineage` (50; per campaign once one exists), `max_pivots_per_day`
(200), `max_search_queries_per_day` (100, shared with discovery), search rate limits, `max_deep_per_hour` (30),
and a batch time budget. A test drives an endless A to B to C world and proves it stops at `max_depth + 1`.

**Campaign correlation** (`hunter/correlate.py`). A pair of domains joins a campaign through one strong link
(same phone/WhatsApp number, Telegram handle, payment id, crypto wallet, analytics id, email, credential
endpoint, or distinctive page template) or two independent medium links (IP, nameserver, certificate, redirect
target, social profile). Weak links (registrar, CDN, a link to the same site, mass-market DNS) are shown as
detail and never merge anything. A node's weight decays above 5 users and is ignored above 20. Every derived
edge cites a correlation evidence row. Campaigns only grow or merge; splitting is an analyst's decision.

**Security controls.** One definition of "public address" (`watchtower/discovery/safe_fetch.is_public_ip`) for
fetching, TLS and queueing: refuses private, loopback, link-local, carrier-grade NAT (incl. Alibaba metadata),
documentation, multicast, IPv4-mapped, 6to4, Teredo and NAT64 ranges. DNS is resolved once and pinned for the
connection; every redirect is revalidated; responses are streamed with a size cap on decoded bytes (decompression
bombs), a content-type allowlist (no executables or archives), a wall-clock deadline, and a robots policy (the
landing page is a recorded targeted inspection; extra pages always obey robots.txt). GET only: forms are
parsed, never filled or submitted. No JavaScript is executed. No CAPTCHA, login or payment handling. Page text
is data: nothing from a page reaches a shell, SQL string or prompt. Personal data (page text, contact
identifiers, rejected input) has a retention limit and an audited purge. API responses never include config,
paths or environment; writes refuse on ephemeral storage; analyst identity is the authenticated account when
auth is on, else a typed name labelled `self_asserted`.

## Tests

540 hunter tests in 14 files (582 collected in the repo; the four legacy suites also pass):
normalization 45, queue 17, pre-score/config/permutations 31, discovery and failure isolation 23, enrichment 53,
page acquisition 40, signals 104, scoring 34, pivots 32, campaigns 29, operations (changes, alerts, retention,
search discovery, coverage, scheduler) 32, API 25, security and ethics 60, and the end-to-end definition of done 15.

```bash
python -m pytest -q                               # everything
python -m pytest tests/test_hunter_end_to_end.py  # the scheduler-only scenario, start to finish
python smoke_test.py && python sweep_test.py && python web_test.py && python scamscan_test.py
python -m flake8 . --select=E9,F63,F7,F82
python -m mypy hunter --ignore-missing-imports
```

All of it runs offline: crt.sh, registries, sites and search are mock transports; DNS and TLS are fakes.

## Known limitations

- **crt.sh is unreliable for common terms** (HTTP 502 on `%mpesa%`-style wildcards): CT runs report `degraded`,
  keep their cursors, and lose nothing, but coverage is thin until a second CT source exists.
- **DuckDuckGo soft-blocks bots**, answering "no results" or HTTP 202. The backend only believes "no results"
  after a quoted control query succeeds; otherwise it reports `blocked` and defers. Expect search-driven
  discovery to be intermittent without a better source.
- **No JavaScript rendering.** Single-page-app phishing pages are seen as empty shells and flagged, not scored clean.
- **Bot-protected sites** (for example behind Incapsula or Cloudflare challenges) return `unassessed`; nothing
  tries to get past a challenge.
- RDAP age needs the registry to publish RDAP; `.test` and some ccTLDs do not. The registrable domain is found
  without the Public Suffix List, using a short list of two-part suffixes.
- No favicon hash, no WHOIS-registrant correlation (mostly redacted), no campaign splitting, no analyst-user
  accounts (one shared account when auth is on), Kiswahili phrase rules not yet reviewed by a native speaker.
- Python 3.9 compatible (the dev machine) and 3.10 (CI).

## Optional future enhancements

A second CT source (Certstream, or crt.sh's read-only Postgres replica); a headless-browser acquirer behind the
same `ContentAcquisitionProvider` interface; a paid reverse-IP or passive-DNS adapter; favicon hashing; threat-feed
evidence (`threat_feed_hit` is already read by the scorer when present); per-analyst accounts; campaign splitting
and a review workflow; a native-speaker review of the Kiswahili and Sheng rules.
