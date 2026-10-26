# Watchtower / ScamScan

> **African Financial Fraud Intelligence Platform**

See [`AUDIT.md`](AUDIT.md) for the current functional verification boundary,
UI/UX review, integration recommendations, and prioritised remediation plan.

This repository contains two complementary tools for threat intelligence:

- **Watchtower**: Monitors news, regulatory sources, and sanctions lists for emerging threats
- **ScamScan**: Actively hunts and analyzes phishing/scam websites targeting African financial services

## Recent Improvements (Evidence-Based Detection)

The platform has been upgraded from simple keyword detection to a comprehensive **evidence-based threat intelligence engine**:

### New Evidence Model
- **Identity Evidence**: Brand impersonation, typosquatting, lookalike domains
- **Infrastructure Evidence**: DNS, IP, ASN, hosting, TLS certificates, domain age
- **Content Evidence**: Forms, payment requests, credential harvesting, page fingerprints
- **Reputation Evidence**: PhishTank, OpenPhish, URLhaus, ThreatFox, Spamhaus integration
- **Campaign Evidence**: Related infrastructure, shared artifacts, campaign clustering

### New Verdict Categories
Instead of simple 0-100 scores, the system now provides explainable verdicts:
- `CONFIRMED_MALICIOUS` - Strong independent evidence exists
- `HIGH_RISK` - Multiple suspicious indicators
- `SUSPICIOUS` - Some concerning indicators  
- `LOW_RISK` - Limited evidence of malicious activity
- `VERIFIED_OFFICIAL` - Domain independently validated
- `UNKNOWN` - Insufficient evidence (Unknown ≠ Safe)

### New Modules
- `core/evidence.py` - Evidence collection and verdict computation
- `intelligence/threat_feeds.py` - External threat intelligence integration
- `enrichment/engine.py` - DNS, RDAP, TLS, IP enrichment
- `hunters/` - Discovery modules (search engines, CT logs, feeds)
- `detection/` - Analysis modules (brand impersonation, content analysis)
- `campaigns/` - Campaign clustering and relationship mapping

See [IMPROVEMENTS.md](IMPROVEMENTS.md) for the complete roadmap.

---

## Quick Start

```bash
python run.py serve      # web UI at http://127.0.0.1:8000
python run.py sweep "beneficial ownership Kenya" --hours 168
```

```bash
python run.py serve      # web UI at http://127.0.0.1:8000
python run.py sweep "beneficial ownership Kenya" --hours 168    # or CLI
```

## Setup

```bash
bash setup.sh              # creates .venv, installs deps, runs all tests
source .venv/bin/activate
export GEMINI_API_KEY=...          # optional; free tier at aistudio.google.com
python run.py serve
```

Open <http://127.0.0.1:8000>, type a query, hit Sweep. No config file needed,
no API key required to get results.

## The web UI

A sweep takes a while, so nothing blocks: results stream over SSE and each
source fills its lane as it reports in. Four views — **Sweep** and **Archive**
on the watchtower side, **Queue** and **Score** on the scamscan side.

Budget 30-60s without model scoring. With it, expect longer: scoring is one
call per candidate and a free-tier Gemini key is rate limited per minute, so a
25-item `--max-ai` pass can add several minutes. Lower `--max-ai` if you want it
snappier — the keyword prefilter already ranks everything, so the model is only
re-ordering the top of the list.

Controls map to the CLI flags: lookback window, which sources to hit, whether to
read full article bodies, whether to score with a model. Options that need a key
you haven't set are disabled with a tooltip saying which one.

```bash
python run.py serve --host 0.0.0.0 --port 9000
```

It binds to localhost by default and there is no authentication there. Off
localhost it **fails closed**: with no `WATCHTOWER_PASSWORD` set it serves 503
rather than exposing endpoints that spend API credits and a review queue holding
personal data.

That's it. No config needed for sweeps, no API key required to get results.
Without a key you lose relevance scoring, summaries and entity extraction, and
fall back to keyword-overlap ranking. Scoring runs on **Gemini or Anthropic** —
whichever key is set, Gemini first because it has a free tier. `python run.py
models` lists what your key can reach.

## What a sweep does

```
fan out across sources -> dedupe -> fetch bodies -> clean
    -> keyword prefilter -> the model scores the survivors -> rank -> report
```

Results print to the terminal; a full markdown report lands in `out/`.

## Free-first impersonation investigations

The **Discover** view now runs an evidence graph investigation rather than a
DuckDuckGo-results classifier. It remains useful with an empty `.env`:

```text
CT + Common Crawl + open-web/social indexes
  -> canonical domains and social accounts
  -> RDAP + DNS + live TLS + Team Cymru ASN context
  -> URLhaus + ThreatFox
  -> SSRF-safe bounded page inspection
  -> phones, email, social, payment, analytics, favicon and HTML entities
  -> exact-identifier and template correlation
  -> evidence score, machine verdict, campaigns and coverage
```

Discovery is iterative rather than a single search-engine request. Public
indexes (DuckDuckGo and Common Crawl) seed candidates, while the free indexed
social adapter adds public social links where available. Every safe page observation feeds domains, accounts, phones and email addresses
back into bounded reverse-pivot rounds; each new domain is enriched and
inspected before the next round. The API reports round counts, page/request
budgets and a termination reason so a partial run cannot be mistaken for a
clean result. Provider calls are retried only when idempotent, cached,
rate-limited and capped by the configured external-request budget.

SocialCrawl remains an optional accelerator; free public providers are the
default path and no authenticated social access is bypassed.

DuckDuckGo is one provider in this pipeline. A failure is stored as a source
run and shown as failed, limited, or unavailable; it is never converted to a
zero-result success. TikTok, Facebook, and Instagram are deliberately marked
`web_index_only`: Watchtower records public links and indexed profiles but does
not bypass login, CAPTCHA, or platform controls.

No commercial API is required by the investigation engine. Optional legacy
Watchtower/ScamScan integrations remain available, but missing credentials do
not disable CT, Common Crawl, RDAP, DNS, TLS, URLhaus, ThreatFox, safe fetching,
local correlation, or SQLite graph storage.

Important modules:

```text
watchtower/discovery/base.py          provider/run contracts
watchtower/discovery/providers.py     free discovery and enrichment adapters
watchtower/discovery/safe_fetch.py    SSRF and resource-bounded HTTP
watchtower/discovery/page_analysis.py deterministic HTML/entity analysis
watchtower/discovery/orchestrator.py  bounded pipeline and reverse pivots
watchtower/discovery/scoring.py       evidence-based machine verdicts
investigation/storage.py              SQLite entities/evidence/edges/campaigns
```

| Source | What it gives you | Key needed |
|---|---|---|
| `gdelt` | global news, all languages, 15-min lag | no |
| `google_news` | broad news, good local outlet recall | no |
| `wikipedia` | entity background, disambiguation | no |
| `hackernews` | tech and fintech chatter | no |
| `gleif` | legal entity identifiers, corporate structure | no |
| `sec_edgar` | US filings full-text | no |
| `opensanctions` | sanctions, PEP and watchlist matches | `OPENSANCTIONS_API_KEY` |
| `opencorporates` | company registry records | `OPENCORPORATES_API_KEY` |
| `reddit` | subreddit search via the official API | `REDDIT_CLIENT_ID` + `_SECRET` |
| `x` | posts via X's official paid API | `X_BEARER_TOKEN` |
| `socialcrawl` | public posts across multiple social platforms (opt-in; paid credits) | `SOCIALCRAWL_API_KEY` |

`python run.py sources` prints this list with the keys you actually have set,
and marks the ones that will skip themselves.

```bash
python run.py sources                                     # list them
python run.py sweep "acme ltd" --sources gdelt,opensanctions
python run.py sweep "acme ltd scam" --sources socialcrawl --hours 168
python run.py sweep "crypto licensing" --hours 720 --top 40
python run.py sweep "quick look" --no-fetch --no-ai       # seconds, headlines only
python run.py sweep "acme ltd" --save                     # keep it in the archive
```

Flags: `--hours` lookback, `--limit` per-source cap, `--max-ai` cap on items
sent to the model, `--top` how many print, `--sources` which backends.

GDELT accepts operators inside the query string: `sourcecountry:KE`,
`sourcelang:english`, `domain:example.co.ke`, `"exact phrase"`, `(a OR b)`.

## Scheduled monitoring

Once a sweep shows a topic is worth watching, move it into `config.yaml` and let
it run on a schedule.

```bash
python run.py run                # collect + enrich + alert
python run.py search "kenya AND (fraud OR laundering)"
python run.py stats
```

`.github/workflows/monitor.yml` runs this twice daily on a free GitHub runner
and commits results back to the repo. That's the whole deployment — no server.

Adapters for scheduled mode, all in `adapters/`:

| Adapter | What it watches | Notes |
|---|---|---|
| `rss` | any feed | start here — cheapest source that exists |
| `gdelt` | standing GDELT queries | takes GDELT's own `timespan` |
| `webpage` | listing pages with no feed | link differ, survives redesigns; reads PDFs |
| `social` | subreddits via the official API | enforces `RETENTION_DAYS` on every run |

Each consults `store.is_seen()`, so a poll that finds nothing new is cheap.
Unlike sweep sources they never raise on an ordinary failure: a scheduled run is
unattended, and one dead feed at 03:00 must not stop the other eleven.

Point `rss` at a self-hosted [RSSHub](https://github.com/DIYgod/RSSHub) and a
lot of feed-less sites become feeds.

## Design notes

**Dedupe is on content hash, not URL.** One story syndicated to five outlets
under five URLs is one story.

**Two ranking passes.** A free keyword pass runs over everything; only plausible
candidates reach the model. That's what keeps a sweep cheap.

**Source diversity cap.** Three results per domain up top, so wire copy can't
occupy your entire first page.

**The model sits in scoring only** — not in fetching, and not in parsing HTML
where a CSS selector works. Cost controls already in the code: text is cleaned
and truncated first, the instructions stay byte-identical across a run so the
prompt cache holds, a cheap model triages and only items above `escalate_above`
get a deeper pass, and the JSON shape is enforced by the API so nothing
regex-parses model prose.

**robots.txt goes through the same client as everything else.** urllib's
`RobotFileParser.read()` opens its own connection, ignores your user agent and
timeout, and treats a 403 as "disallow everything" — which silently kills every
fetch behind a proxy. This bug was live in the first version and the test caught
it.

## Tests

```bash
python smoke_test.py        # store, dedupe, FTS5, alerts, adapters, retention
python sweep_test.py        # backend parsers, dedupe, concurrent fetch,
                            # ranking, both renderers
python web_test.py          # endpoints, SSE contract, validation,
                            # path traversal, frontend wiring, both UI sides
python scamscan_test.py     # scamscan: scoring, lexicon, schemas, silent zeros
```

Each suite prints its own total. They need no network and no API key — verified
by running them with `.env` moved aside.

Both `sweep_test.py` and `web_test.py` inject an `httpx.MockTransport`, so only
the network is replaced — the code under test is the real thing, including the
FastAPI app and the SSE stream. If they pass but a live sweep returns nothing,
the problem is the remote API or your connection, not the install.

The web UI has been rendered and checked in Chrome at 1440, 820 and 380px,
including the empty, connection-lost and no-source-selected states, and both the
watchtower and scamscan sides. Scheduled mode is covered too: `smoke_test.py`
exercises all four adapters against a mock transport, including the retention
purge and its removal from the FTS index.

## Before you point it at anything

- `obey_robots: true` stays on. It's the line between automated collection and
  unauthorised access if anyone ever asks.
- Rate limiting is per domain, not global, and thread-safe.
- Put a real contact address in `WATCHTOWER_CONTACT` in `.env`. `config.yaml`
  interpolates it into the user agent, so a reachable address gets sent without
  being committed. SEC EDGAR answers 403 without one.
- Social posts are personal data. Under Kenya's Data Protection Act 2019 you
  need a lawful basis, a stated purpose and a retention limit. `RETENTION_DAYS`
  in `adapters/social.py` is enforced on every scheduled run.
- Instagram, TikTok, LinkedIn, Facebook, Mastodon and Bluesky are absent on
  purpose. They either prohibit scraping or provide inconsistent unauthenticated
  search, which is the worst failure mode for monitoring. Brave web search is
  also retired from the default path because it is metered; Common Crawl,
  DuckDuckGo and direct page inspection provide the stable free fallback.
- Sweeping a named private individual is a different activity from sweeping a
  topic or a company, legally and ethically. Know which one you're doing.

## Working on this with Claude Code

`CLAUDE.md` in the repo root is loaded automatically each session. It carries the
architecture, the decisions that shouldn't be silently reversed, the UI design
tokens, and the known gaps. Keep it current — when you change something
structural, update it in the same commit.

```bash
cd watchtower
git init && git add -A && git commit -m "initial"
claude
```

Run the three test suites after every change. They need no network and no API
key, so there's no excuse to skip them.

## Extending

Add a source by writing one function in `core/sources.py` with the signature
`(query, fetcher, hours, limit) -> list[Item]` and registering it in `BACKENDS`.
Nothing else changes.

## Autonomous hunting

Beyond sweeps and the scam-site queue, Mnara can hunt on its own: it discovers candidate impersonation
infrastructure (certificate transparency, typo generation, public search, pivots on shared phone numbers and
payment ids), explains every score, links related sites into campaigns and keeps the evidence.
Start it with `python run.py hunt`; see [HUNTER.md](HUNTER.md).
