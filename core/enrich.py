"""The scoring layer: messy prose in, typed records out.

Runs on Gemini or Anthropic, picked by whichever key is set (see
`available_provider`). Everything below is true of both paths.

Cost discipline baked in:
  - Text is already cleaned and truncated before it gets here.
  - The instructions are constant across every item in a run, and `focus` goes
    in the user turn rather than the system block, so the cached prefix stays
    identical — explicit `cache_control` on Anthropic, implicit caching on
    Gemini. Either way the schema and watchlist aren't re-billed per article.
  - A cheap model triages everything; only items scoring above `escalate_above`
    get a second, deeper pass. On a typical news feed that's under 10%.
  - The JSON shape is enforced by the API — a forced tool call on Anthropic,
    `response_json_schema` on Gemini — so nothing regex-parses model prose.

Two provider differences that bite:
  - Gemini bills *thinking* against `max_output_tokens`, so budgets here are
    sized for thinking plus output, not output alone.
  - 503 UNAVAILABLE is common and transient. It is retried; without that, one
    blip drops an item to its keyword score and quietly reorders the results.
"""

from __future__ import annotations

import json
import logging
import os
import random
import time

class _Lazy:
    """Defer a heavy SDK import to first use. `anthropic` and `google.genai` cost ~1s of start-up between
    them, and most commands (serve, search, the hunter) never call a model. Availability is still decided
    up front with find_spec, so `x is not None` keeps meaning "installed"."""
    def __init__(self, name):
        self._name, self._mod = name, None

    def __getattr__(self, attr):
        if self._mod is None:
            import importlib
            self._mod = importlib.import_module(self._name)
        return getattr(self._mod, attr)


def _lazy(name):
    import importlib.util
    try:
        return _Lazy(name) if importlib.util.find_spec(name) else None
    except (ImportError, ValueError):
        return None


anthropic = _lazy("anthropic")
genai = _lazy("google.genai")
genai_types = _Lazy("google.genai.types") if genai is not None else None  # not _lazy(): find_spec imports the parent package

class _DropThoughtPartWarning(logging.Filter):
    """Silence one specific, per-item SDK warning.

    Gemini 3 models return a `thought_signature` part beside the answer, and the
    SDK warns about "non-text parts" every time .text or .parsed is read. A
    sweep enriches up to --max-ai items, so this is 25 identical lines of noise
    per run about something the code deliberately ignores. Narrow on purpose:
    every other warning from the SDK still comes through.
    """

    def filter(self, record):
        return "non-text parts in the response" not in record.getMessage()


if genai is not None:
    logging.getLogger("google_genai.types").addFilter(_DropThoughtPartWarning())

TRIAGE_MODEL = "claude-haiku-4-5-20251001"
DEEP_MODEL = "claude-sonnet-5"

# Gemini equivalents of the same two tiers. Overridable, because model IDs move
# faster than this file does and a free-tier key does not see all of them —
# `python run.py models` lists what your key can actually reach.
# Verified against a live free-tier key on 2026-08-13. The 2.5 models that used
# to be the obvious defaults now 404 with "no longer available to new users",
# and the Pro models 429 — Pro is not on the free tier. Both of these are flash.
GEMINI_TRIAGE_MODEL = os.environ.get("GEMINI_TRIAGE_MODEL", "gemini-3.5-flash-lite")
GEMINI_DEEP_MODEL = os.environ.get("GEMINI_DEEP_MODEL", "gemini-3.7-flash")

# Free-tier Gemini keys are rate limited per minute, and a sweep enriches up to
# --max-ai items back to back. Without a retry the tail of every sweep would
# come back unscored and look like a run of irrelevant articles. 503 "high
# demand" is the other common one and is not a rate limit — see _is_transient.
RATE_LIMIT_RETRIES = 4


def available_provider(explicit: str = "") -> str:
    """Which provider this process can actually use, in preference order.

    Gemini first when its key is present: it has a usable free tier, and the
    common case for this repo is a depleted Anthropic balance. Set
    WATCHTOWER_LLM_PROVIDER to force one.
    """
    choice = (explicit or os.environ.get("WATCHTOWER_LLM_PROVIDER", "")).lower()
    if choice in ("gemini", "anthropic"):
        return choice
    if os.environ.get("GEMINI_API_KEY") and genai is not None:
        return "gemini"
    if os.environ.get("ANTHROPIC_API_KEY") and anthropic is not None:
        return "anthropic"
    return ""


# The same shape as EXTRACT_TOOL's input_schema. Anthropic gets it as a tool
# that must be called; Gemini gets it as response_json_schema. Both end up
# forcing valid JSON, so neither path ever regex-parses model prose.
RECORD_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "entities": {"type": "array", "items": {"type": "string"}},
        "categories": {"type": "array", "items": {"type": "string"}},
        "relevance": {"type": "integer"},
        "reasoning": {"type": "string"},
    },
    "required": ["summary", "entities", "categories", "relevance"],
}

EXTRACT_TOOL = {
    "name": "record",
    "description": "Record the structured analysis of this document.",
    "input_schema": {
        "type": "object",
        "properties": {
            "summary": {
                "type": "string",
                "description": "Two sentences maximum. What happened and why it matters. No preamble.",
            },
            "entities": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Named people, companies, institutions and jurisdictions. Canonical form, no titles.",
            },
            "categories": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Topic tags from the allowed list in the instructions. Empty if none fit.",
            },
            "relevance": {
                "type": "integer",
                "description": "0-100. How strongly this matches the watchlist and topics of interest. Be harsh: most items should score under 30.",
            },
            "reasoning": {
                "type": "string",
                "description": "One line justifying the relevance score.",
            },
        },
        "required": ["summary", "entities", "categories", "relevance"],
    },
}


def _instructions(watchlist: list[str], categories: list[str]) -> str:
    return f"""You are triaging documents for a monitoring pipeline. For each one, \
record a structured analysis using the `record` tool. Never answer in prose.

Allowed category tags (use only these, or none):
{chr(10).join('- ' + c for c in categories)}

Watchlist terms and entities of interest:
{chr(10).join('- ' + w for w in watchlist) if watchlist else '(none configured)'}

Scoring guidance:
- 80-100: directly names a watchlist entity, or squarely answers the SEARCH FOCUS
- 50-79: strong topical match, no watchlist entity named
- 20-49: loosely related background or context
- 0-19: irrelevant

If a SEARCH FOCUS is given, score against it and treat the watchlist as a \
secondary signal. Otherwise score against the watchlist and topics.

Do not inflate scores. A pipeline that flags everything flags nothing. If the \
text is truncated, paywalled, or is just a headline stub, score it on what is \
actually present rather than guessing at the rest. A page that merely mentions \
the search terms in a navigation menu or unrelated aside is not a match."""


def _fatal_reason(exc) -> str | None:
    """Account-level failures that every later call in this run will hit too.

    A depleted balance or a rejected key is not per-item bad luck: retrying it
    across 25 candidates burns 25 round trips to produce 25 identical errors,
    and leaves the run looking like it was scored when it wasn't. Rate limits
    and timeouts are deliberately NOT fatal — those are worth continuing past,
    and on a free-tier Gemini key a per-minute limit is the normal case rather
    than an outage.
    """
    status = getattr(exc, "status_code", None) or getattr(exc, "code", None)
    msg = str(exc).lower()
    if status in (401, 403) or "api key not valid" in msg or "permission_denied" in msg:
        return "API key was rejected"
    if status == 400 and "credit balance" in msg:
        return "Anthropic credit balance is too low"
    # Gemini reports an exhausted daily free-tier allowance as RESOURCE_EXHAUSTED
    # with a per-day quota metric. Per-minute limits use the same status, so the
    # daily marker is what separates "wait a moment" from "come back tomorrow".
    if "resource_exhausted" in msg or status == 429:
        if "per day" in msg or "perday" in msg or "daily" in msg:
            return "Gemini free-tier daily quota is exhausted"
    return None


def _is_transient(exc) -> bool:
    """Worth trying again in a moment, as opposed to worth giving up on.

    503 UNAVAILABLE ("this model is currently experiencing high demand") is the
    one that matters and it is not a rate limit. It was costing whole items:
    the single most on-topic article in a live sweep took one 503, fell back to
    its keyword score, and ranked below an off-topic story that happened to
    answer on the first try. The run said so in `errors`, so it was not silent
    — but a transient blip should not decide the ranking.
    """
    status = getattr(exc, "status_code", None) or getattr(exc, "code", None)
    msg = str(exc).lower()
    return (status in (429, 500, 502, 503, 504)
            or "resource_exhausted" in msg
            or "unavailable" in msg
            or "internal error" in msg)


class Enricher:
    def __init__(self, watchlist: list[str], categories: list[str],
                 escalate_above: int = 60, api_key: str | None = None,
                 provider: str = ""):
        self.watchlist = watchlist
        self.categories = categories
        self.escalate_above = escalate_above
        self.provider = available_provider(provider)
        if self.provider == "gemini":
            key = api_key or os.environ.get("GEMINI_API_KEY")
            self.enabled = bool(key) and genai is not None
            self.client = genai.Client(api_key=key) if self.enabled else None
            self.triage_model, self.deep_model = GEMINI_TRIAGE_MODEL, GEMINI_DEEP_MODEL
        elif self.provider == "anthropic":
            key = api_key or os.environ.get("ANTHROPIC_API_KEY")
            self.enabled = bool(key) and anthropic is not None
            self.client = anthropic.Anthropic(api_key=key) if self.enabled else None
            self.triage_model, self.deep_model = TRIAGE_MODEL, DEEP_MODEL
        else:
            self.enabled, self.client = False, None
            self.triage_model, self.deep_model = TRIAGE_MODEL, DEEP_MODEL
        self.instructions = _instructions(watchlist, categories)
        # Set once an account-level failure is seen, which also flips `enabled`
        # off so the rest of the run falls back to keyword ranking immediately.
        self.fatal_error: str | None = None

    def _call_gemini(self, model: str, title: str, text: str,
                     focus: str = "") -> dict | None:
        head = f"SEARCH FOCUS: {focus}\n\n" if focus else ""
        last = None
        for attempt in range(RATE_LIMIT_RETRIES):
            try:
                resp = self.client.models.generate_content(
                    model=model,
                    contents=f"{head}TITLE: {title}\n\nBODY:\n{text}",
                    config=genai_types.GenerateContentConfig(
                        # Constant across every item in the run, which is what
                        # makes Gemini's implicit caching fire — the same reason
                        # `focus` stays in the user turn on the Anthropic path.
                        system_instruction=self.instructions,
                        response_mime_type="application/json",
                        response_json_schema=RECORD_SCHEMA,
                        # Thinking is billed against this budget on Gemini 3,
                        # so 1024 (fine for Anthropic, which counts output
                        # only) truncates the JSON and loses the item.
                        max_output_tokens=4096,
                    ),
                )
                # Gemini 3 returns a thought_signature part beside the answer
                # and resp.text warns about dropping it on every single item.
                text = "".join(
                    part.text
                    for cand in (resp.candidates or [])
                    for part in (getattr(cand.content, "parts", None) or [])
                    if getattr(part, "text", None))
                return json.loads(text)
            except Exception as e:
                last = e
                if not _is_transient(e) or _fatal_reason(e):
                    raise
                # Jittered, so 25 candidates in one sweep don't all wake up
                # together and hit the per-minute limit again as a block.
                time.sleep((2 ** attempt) + random.uniform(0, 1))
        raise last

    def _call(self, model: str, title: str, text: str, focus: str = "") -> dict | None:
        if self.provider == "gemini":
            return self._call_gemini(model, title, text, focus)
        # focus goes in the user turn, not the system block, so the cached
        # prefix stays identical across different queries in the same process.
        head = f"SEARCH FOCUS: {focus}\n\n" if focus else ""
        resp = self.client.messages.create(
            model=model,
            max_tokens=1024,
            system=[{
                "type": "text",
                "text": self.instructions,
                # Cached across every item in the run. This is the single
                # biggest cost lever in the whole pipeline.
                "cache_control": {"type": "ephemeral"},
            }],
            tools=[EXTRACT_TOOL],
            tool_choice={"type": "tool", "name": "record"},
            messages=[{
                "role": "user",
                "content": f"{head}TITLE: {title}\n\nBODY:\n{text}",
            }],
        )
        for block in resp.content:
            if block.type == "tool_use":
                return block.input
        return None

    def enrich(self, title: str, text: str, focus: str = "") -> dict:
        """Triage with Haiku, escalate borderline-and-above to Sonnet.

        `focus` is the sweep query: score relevance against it when present,
        against the configured watchlist otherwise.
        """
        if not self.enabled:
            return {"summary": "", "entities": [], "categories": [],
                    "relevance": 0, "skipped": "no API key"}
        try:
            out = self._call(self.triage_model, title, text, focus)
            if out is None:
                return {"summary": "", "entities": [], "categories": [],
                        "relevance": 0, "skipped": "no tool call returned"}
            if out.get("relevance", 0) >= self.escalate_above:
                deep = self._call(self.deep_model, title, text, focus)
                if deep:
                    out = deep
                    out["model"] = self.deep_model
            else:
                out["model"] = self.triage_model
            return out
        except Exception as e:
            fatal = _fatal_reason(e)
            if fatal:
                # Stop trying for the rest of this run rather than repeating a
                # doomed call once per candidate.
                self.enabled = False
                self.fatal_error = fatal
                return {"summary": "", "entities": [], "categories": [],
                        "relevance": 0, "skipped": fatal, "fatal": True}
            return {"summary": "", "entities": [], "categories": [],
                    "relevance": 0, "skipped": f"{type(e).__name__}: {e}"}


BRIEF_INSTRUCTION = (
    "Write a short monitoring brief from the items below. Lead with what "
    "actually changed. Group related items rather than listing them one by "
    "one. Say plainly if nothing significant came through. Do not pad, do "
    "not add a closing summary paragraph, and do not use headers unless "
    "there are genuinely distinct themes."
)


def digest(items: list[dict], api_key: str | None = None,
           provider: str = "") -> str:
    """One narrative brief over a batch. Run this after enrichment, over the
    summaries rather than the full texts, so a 200-item digest stays cheap."""
    which = available_provider(provider)
    if not which:
        return "(digest skipped: set GEMINI_API_KEY or ANTHROPIC_API_KEY)"
    if not items:
        return "(nothing new to report)"

    lines = [
        f"[{i.get('relevance', 0)}] {i.get('title', '')} ({i.get('source', '')})\n"
        f"    {i.get('summary', '') or i.get('text', '')[:200]}"
        for i in items
    ]

    try:
        return _digest_call(which, lines, api_key)
    except Exception as e:
        # The alert list is the deliverable; this narrative brief is a garnish
        # on top of it. Letting a transient 503 here abort `run.py alert` means
        # a scheduled run produces no digest file at all and the watchlist hits
        # go unrecorded — losing the alert to save the prose.
        return f"(digest unavailable: {type(e).__name__}: {str(e)[:200]})"


def _digest_call(which: str, lines: list[str], api_key: str | None) -> str:
    if which == "gemini":
        client = genai.Client(api_key=api_key or os.environ.get("GEMINI_API_KEY"))
        resp = client.models.generate_content(
            model=GEMINI_DEEP_MODEL,
            contents="\n".join(lines),
            config=genai_types.GenerateContentConfig(
                system_instruction=BRIEF_INSTRUCTION, max_output_tokens=4096),
        )
        return resp.text or ""

    client = anthropic.Anthropic(api_key=api_key or os.environ.get("ANTHROPIC_API_KEY"))
    resp = client.messages.create(
        model=DEEP_MODEL,
        max_tokens=1500,
        system=(
            "Write a short monitoring brief from the items below. Lead with what "
            "actually changed. Group related items rather than listing them one by "
            "one. Say plainly if nothing significant came through. Do not pad, do "
            "not add a closing summary paragraph, and do not use headers unless "
            "there are genuinely distinct themes."
        ),
        messages=[{"role": "user", "content": "\n".join(lines)}],
    )
    return "".join(b.text for b in resp.content if b.type == "text")
