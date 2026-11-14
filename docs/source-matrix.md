# Source matrix: what works keyless, and from where

Status: **the Render run has not been done yet.** The table below is from a developer laptop
and is provisional. Search engines and platforms treat datacenter addresses differently from
home ones, so nothing here should be built on until the same run is repeated on Render.

## How to run it on Render

1. Deploy this branch (or merge it) so the Render service has the code.
2. While signed in to the app, open `/api/admin/source-matrix` on the Render URL. The first
   visit starts the run; the page refreshes itself and shows the finished matrix after two to
   four minutes. Add `?fresh=1` to run it again, `?format=json` for the raw rows.
3. Paste the result into this file under "Render run" and commit it.

From a shell on the instance, `python -m social.spike` prints the same thing.

## What the test does

- Sends an honest, identifying User-Agent. No browser disguise, no proxy, no sign-in, no
  retries, no challenge solving. A source that only answers a disguised client counts as blocked.
- Gives each search engine a control query that must return results. An engine that fails it
  is soft-blocking, and its empty answers are reported as blocked, not as "nothing found".
- Does not probe Facebook or Instagram pages, X syndication, or TikTok tag/search pages.
  Those are excluded by policy (see `CLAUDE.md`), so their absence here is a decision, not a result.

## Render run

_Pending._

## Laptop run (provisional, home connection)

What it showed, in plain terms:

- **DuckDuckGo's HTML and Lite pages answer an honest client, but only for about three
  site-restricted searches in a row.** The fourth onward got a challenge page (HTTP 202), even
  at one request every five seconds. Reddit, TikTok and X came back; Facebook, Instagram and the
  recency-filtered query were challenged purely because they were asked later.
- **Bing answered the control query but returned "no results" for every site-restricted query**,
  and its robots.txt disallows `/search`. Not usable as tested.
- **Mojeek refused the client outright** (HTTP 403), and its robots.txt disallows `/search`.
- **The `ddgs` library the app uses today returned results for all five platforms.** It differs
  from the direct probes in one way that matters: it presents itself as a browser.
- **Reddit refused every unauthenticated endpoint**: 403 on `search.json`, `new.json` and
  `search.rss`, 429 on the subreddit feed, and a redirect to the login page on old.reddit.
  This was from a home connection, so a datacenter is unlikely to do better.
- **TikTok oEmbed answers but carries no author, title or text**, only an embed player.
- **X publish oEmbed works**: author name, author URL, and the post text inside the embed HTML.

### Run from: local

- When: 2026-11-14T05:46:19+00:00 (171s)
- Test term: `Fuliza`
- Client: `Mnara-SourceMatrix/0.1 (keyless feasibility test; +https://github.com/NADUPA-AFRICA-FOUNDATION/watchtower-main)` — honest identifier, no browser disguise, no proxy, no retries
- Verdicts: `ok` real results came back; `no_results` answered but found nothing; `partial` answered without the fields that matter; `blocked` refused, challenged, walled, or silently empty; `not_tested` nothing to test with

#### Discovery

| Source | Target | HTTP | Verdict | What came back | Why / note | robots.txt |
|---|---|---|---|---|---|---|
| duckduckgo_html | control query | 200 | **ok** | 53 links | — | allows |
| duckduckgo_html | reddit | 200 | **ok** | 10 reddit.com links, e.g. https://www.reddit.com/r/Kenya/comments/11lx29r/fuliza_system_failure_ | — | allows |
| duckduckgo_html | tiktok | 200 | **ok** | 7 tiktok.com links, e.g. https://www.tiktok.com/@fuliza.a | — | allows |
| duckduckgo_html | x | 200 | **ok** | 9 x.com links, e.g. https://x.com/Fuliza | — | allows |
| duckduckgo_html | facebook | 202 | **blocked** | 0 facebook.com links | HTTP 202 (challenge page) | allows |
| duckduckgo_html | instagram | 202 | **blocked** | 0 instagram.com links | HTTP 202 (challenge page) | allows |
| duckduckgo_html | reddit + recency filter | 202 | **blocked** | 0 reddit.com links | HTTP 202 (challenge page) | allows |
| duckduckgo_lite | control query | 200 | **ok** | 21 links | — | allows |
| duckduckgo_lite | reddit | 200 | **ok** | 10 reddit.com links, e.g. https://www.reddit.com/r/Kenya/comments/11lx29r/fuliza_system_failure_ | — | allows |
| duckduckgo_lite | tiktok | 200 | **ok** | 7 tiktok.com links, e.g. https://www.tiktok.com/@fuliza.a | — | allows |
| duckduckgo_lite | x | 200 | **ok** | 9 x.com links, e.g. https://x.com/Fuliza | — | allows |
| duckduckgo_lite | facebook | 202 | **blocked** | 0 facebook.com links | HTTP 202 (challenge page) | allows |
| duckduckgo_lite | instagram | 202 | **blocked** | 0 instagram.com links | HTTP 202 (challenge page) | allows |
| duckduckgo_lite | reddit + recency filter | 202 | **blocked** | 0 reddit.com links | HTTP 202 (challenge page) | allows |
| bing | control query | 200 | **ok** | 40 links | — | disallows |
| bing | reddit | 200 | **no_results** | 0 reddit.com links | the engine itself says there are no results | disallows |
| bing | tiktok | 200 | **no_results** | 0 tiktok.com links | the engine itself says there are no results | disallows |
| bing | x | 200 | **no_results** | 0 x.com links | the engine itself says there are no results | disallows |
| bing | facebook | 200 | **no_results** | 0 facebook.com links | the engine itself says there are no results | disallows |
| bing | instagram | 200 | **no_results** | 0 instagram.com links | the engine itself says there are no results | disallows |
| bing | reddit + recency filter | 200 | **no_results** | 0 reddit.com links | the engine itself says there are no results | disallows |
| mojeek | control query | 403 | **blocked** | — | HTTP 403 (refused) | disallows |
| mojeek | reddit | — | **blocked** | — | engine control query failed; not sent | disallows |
| mojeek | tiktok | — | **blocked** | — | engine control query failed; not sent | disallows |
| mojeek | x | — | **blocked** | — | engine control query failed; not sent | disallows |
| mojeek | facebook | — | **blocked** | — | engine control query failed; not sent | disallows |
| mojeek | instagram | — | **blocked** | — | engine control query failed; not sent | disallows |
| mojeek | reddit + recency filter | — | **blocked** | — | engine control query failed; not sent | disallows |
| ddgs library (current app path) | reddit | — | **ok** | 10 links; title+snippet present | — | n/a (library, browser-like client) |
| ddgs library (current app path) | tiktok | — | **ok** | 10 links; title+snippet present | — | n/a (library, browser-like client) |
| ddgs library (current app path) | x | — | **ok** | 7 links; title+snippet present | — | n/a (library, browser-like client) |
| ddgs library (current app path) | facebook | — | **ok** | 10 links; title+snippet present | — | n/a (library, browser-like client) |
| ddgs library (current app path) | instagram | — | **ok** | 10 links; title+snippet present | — | n/a (library, browser-like client) |

#### Discovery + enrichment

| Source | Target | HTTP | Verdict | What came back | Why / note | robots.txt |
|---|---|---|---|---|---|---|
| reddit search.json | Fuliza | 403 | **blocked** | — | HTTP 403 (refused) | — |
| reddit subreddit new.json | r/Kenya | 403 | **blocked** | — | HTTP 403 (refused) | — |
| reddit search.rss | Fuliza | 403 | **blocked** | — | HTTP 403 (refused) | — |
| reddit subreddit new.rss | r/Kenya | 429 | **blocked** | — | HTTP 429 (rate limited) | — |
| reddit old.reddit search.json | Fuliza | 200 | **blocked** | — | redirected to a login page | — |

#### Enrichment

| Source | Target | HTTP | Verdict | What came back | Why / note | robots.txt |
|---|---|---|---|---|---|---|
| reddit permalink.json | one post | — | **not_tested** | — | no listing endpoint returned a post to follow | — |
| tiktok oEmbed | one public post | 200 | **partial** | fields: html, provider_name | answers, but with no author, title or text: only an embed player | — |
| x publish oEmbed | one public post | 200 | **ok** | fields: author_name, author_url, html, provider_name; post text is inside html | — | — |

#### Not probed (excluded by policy, not by test)

- **facebook**: public page / post HTML, Page Plugin embed
- **instagram**: public post / profile HTML, embedded JSON
- **x**: syndication (embedded tweet/timeline) endpoints
- **tiktok**: tag and search pages (embedded JSON state)
