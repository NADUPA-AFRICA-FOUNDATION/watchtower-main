/* Watchtower frontend. No framework, no build step — open the page and it works.
   The sweep arrives over SSE, so sources fill their lane as each one lands
   rather than everything appearing at once after a minute of nothing. */

const $ = (s) => document.querySelector(s);
const el = (t, cls, txt) => {
  const n = document.createElement(t);
  if (cls) n.className = cls;
  if (txt != null) n.textContent = txt;
  return n;
};

// Provider and page-inspection URLs are untrusted evidence.  Keep them
// clickable for normal web links, but never turn a javascript:, data:, file:
// or other active-content value into an executable anchor.
function safeHref(value) {
  if (typeof value !== "string" || !value.trim()) return "#";
  try {
    const parsed = new URL(value, window.location.origin);
    return parsed.protocol === "http:" || parsed.protocol === "https:"
      ? parsed.href : "#";
  } catch { return "#"; }
}

const BAND_COLOUR = {
  HIGH: "var(--high)", MED: "var(--med)", LOW: "var(--low)", WEAK: "var(--weak)",
};
const BAND_SEGMENTS = { HIGH: 5, MED: 4, LOW: 2, WEAK: 1 };

let selected = new Set();
let hours = 72;
let stream = null;
let capabilities = {};
let previewUrls = new Set();
let sweepLimit = 20;
let maxAi = 8;

const MONITOR_PREFS_KEY = "mnara-monitor-preferences";

function readMonitorPrefs() {
  try {
    const value = JSON.parse(window.localStorage.getItem(MONITOR_PREFS_KEY) || "null");
    return value && typeof value === "object" ? value : {};
  } catch { return {}; }
}

function saveMonitorPrefs() {
  try {
    window.localStorage.setItem(MONITOR_PREFS_KEY, JSON.stringify({
      hours, sweepLimit, maxAi, sources: [...selected],
    }));
  } catch { /* private browsing may disable storage; controls still work */ }
}

function syncSourceChips() {
  document.querySelectorAll("#sweep-form [data-source]").forEach((chip) => {
    const on = selected.has(chip.dataset.source);
    chip.classList.toggle("is-on", on);
    chip.setAttribute("aria-pressed", String(on));
  });
}

/* ------------------------------------------------------------ appearance */

const THEME_KEY = "mnara-theme";
const root = document.documentElement;
const themeToggle = $("#theme-toggle");

function applyTheme(theme) {
  const terminal = theme === "terminal";
  root.dataset.theme = terminal ? "terminal" : "light";
  if (!themeToggle) return;
  themeToggle.setAttribute("aria-pressed", String(terminal));
  themeToggle.setAttribute("aria-label", terminal
    ? "Switch to light theme" : "Switch to terminal theme");
  themeToggle.textContent = terminal ? "[ LIGHT MODE ]" : "[ TERMINAL MODE ]";
}

applyTheme(window.localStorage.getItem(THEME_KEY) || "light");
themeToggle?.addEventListener("click", () => {
  const next = root.dataset.theme === "terminal" ? "light" : "terminal";
  applyTheme(next);
  window.localStorage.setItem(THEME_KEY, next);
});

/* ------------------------------------------------------------ bootstrap */

async function init() {
  // Match the terminal's default: body text is required for useful scoring.
  // Keep the HTML control unchecked for a fast no-JS fallback, then opt in once
  // the capability handshake confirms this is the interactive monitor.
  $("#fetch-bodies").checked = true;
  let data;
  try {
    data = await (await fetch("/api/sources")).json();
  } catch {
    $("#ai-status").textContent = "server unreachable";
    return;
  }
  capabilities = data;
  refreshSystemHealth(data);

  fetch("/api/stats")
    .then((response) => response.ok ? response.json() : Promise.reject())
    .then((stats) => {
      ["total", "enriched", "unalerted", "sources"].forEach((key) => {
        const target = $(`#stat-${key}`);
        if (target) target.textContent = Number(stats[key] || 0).toLocaleString();
      });
    })
    .catch(() => {
      document.querySelectorAll(".platform-stats strong").forEach((node) => {
        node.textContent = "Unavailable";
      });
    });

  const unavailable = data.sources.filter((s) => s.available === false);
  const availableCount = data.sources.length - unavailable.length;
  const statusDetails = $("#status-details");
  statusDetails.replaceChildren(
    el("li", null, `${availableCount} sources ready`),
    ...(unavailable.length ? [el("li", null,
      `${unavailable.length} optional integration${unavailable.length === 1 ? "" : "s"} not configured`)] : []),
    el("li", null, data.ai_available
      ? `Model-assisted ranking ready (${data.ai_provider})` : "Using built-in keyword ranking"),
    el("li", null, data.ephemeral_storage
      ? "Session-only mode — saved results and analyst verdicts are unavailable"
      : "Saved results and analyst verdicts are ready"),
  );
  $("#system-status-summary").textContent =
    `Ready · ${availableCount} source${availableCount === 1 ? "" : "s"} active`;

  const box = $("#sources");
  const sanctionsBox = $("#sanctions-source");
  const sanctionsNote = $("#sanctions-note");
  const socialBox = $("#social-source");
  const socialNote = $("#social-note");
  const monitorSources = data.sources.filter((s) => s.surface !== "investigation");
  const socialNames = new Set(["social_web_index", "socialcrawl", "reddit", "x"]);
  // Investigation providers (DNS, RDAP, CT, threat intelligence, etc.) pivot
  // from domains and belong to the Discover workflow. They used to appear as
  // Monitor chips even though /api/sweep cannot execute them; selecting one
  // made the entire EventSource request fail with "unknown source".
  monitorSources.forEach((s) => {
    const isSanctions = s.name === "opensanctions";
    const chip = el("button", "chip", isSanctions ? "OpenSanctions" : s.name);
    chip.type = "button";
    chip.dataset.source = s.name;
    // Gate on the key actually being present, not on whether the source is a
    // default. opensanctions is both, so the old `needs_key && !default` guard
    // never fired and it shipped selected but dead.
    const usable = s.available !== false;
    // The free indexed-social adapter is opt-in for CLI sweeps (it uses an
    // external search client), but the web's Social media signals mode should
    // work out of the box without a paid key.
    const on = (s.default || s.name === "social_web_index") && usable;
    chip.setAttribute("aria-pressed", String(on));
    if (on) { chip.classList.add("is-on"); selected.add(s.name); }
    if (!usable) {
      chip.disabled = true;
      chip.title = `Set ${s.key_name || "the API key"} to enable`;
      if (isSanctions) {
        sanctionsNote.textContent =
          `Set ${s.key_name || "OPENSANCTIONS_API_KEY"} to search sanctions, PEP and watchlist records.`;
      }
      if (socialNames.has(s.name) && s.key_name) {
        socialNote.textContent =
          `${s.name} is unavailable until ${s.key_name} is configured. SocialCrawl uses paid credits; other public social sources remain independent.`;
      }
    } else if (isSanctions) {
      sanctionsNote.textContent =
        "Ready — include OpenSanctions in this sweep for sanctions, PEP and watchlist matches.";
    } else if (socialNames.has(s.name) && s.name === "socialcrawl") {
      socialNote.textContent =
        "Ready — SocialCrawl searches public posts across supported networks. Each request consumes credits.";
    } else if (s.name === "social_web_index") {
      socialNote.textContent =
        "Ready — free indexed social leads across TikTok, Instagram, Facebook, Telegram, WhatsApp, X and YouTube.";
    }
    chip.onclick = () => {
      chip.classList.toggle("is-on");
      const on = chip.classList.contains("is-on");
      chip.setAttribute("aria-pressed", String(on));
      on ? selected.add(s.name) : selected.delete(s.name);
      saveMonitorPrefs();
    };
    (isSanctions ? sanctionsBox : socialNames.has(s.name) ? socialBox : box).append(chip);
  });

  // Keep a user's source mix and depth settings between visits, but discard
  // providers that are no longer in the server capability response.
  const prefs = readMonitorPrefs();
  if (Number.isInteger(Number(prefs.hours)) && Number(prefs.hours) >= 24 && Number(prefs.hours) <= 8760) {
    hours = Number(prefs.hours);
    const windowButton = document.querySelector(`#window button[data-h="${hours}"]`);
    if (windowButton) windowButton.click();
  }
  if (Number.isInteger(Number(prefs.sweepLimit))) sweepLimit = Math.max(1, Math.min(250, Number(prefs.sweepLimit)));
  if (Number.isInteger(Number(prefs.maxAi))) maxAi = Math.max(0, Math.min(100, Number(prefs.maxAi)));
  $("#sweep-limit").value = sweepLimit;
  $("#max-ai").value = maxAi;
  if (Array.isArray(prefs.sources)) {
    const available = new Set(data.sources.filter((s) => s.available !== false).map((s) => s.name));
    selected = new Set(prefs.sources.filter((name) => available.has(name)));
    syncSourceChips();
  }
  // Persist normalized values after applying preferences. This prevents the
  // lookback button handler from overwriting a saved source mix during restore.
  saveMonitorPrefs();

  // On a serverless host the archive lives in /tmp and does not survive between
  // requests. Saying nothing would let someone tick "Keep results", see it
  // succeed, and find an empty Archive tab later — a silent data loss.
  if (data.ephemeral_storage) {
    const keep = $("#keep");
    keep.checked = false;
    keep.disabled = true;
    keep.closest(".toggle").title =
      "This deployment has no persistent disk — saved results are lost between requests.";
    const note = el("p", "hint warn-note",
      "Storage on this host is temporary: anything you keep is lost between requests.");
    $("#sweep-form").append(note);
  }

  // Name the provider actually in use. The label said "Score with Claude" long
  // after a Gemini key would drive it, which is the kind of drift that makes
  // someone doubt what the rest of the page is telling them.
  const provider = { gemini: "Gemini", anthropic: "Claude" }[data.ai_provider];
  if (!data.ai_available) {
    $("#use-ai").checked = false;
    $("#use-ai").disabled = true;
    $("#use-ai").closest(".toggle").title =
      "Set GEMINI_API_KEY (free tier) or ANTHROPIC_API_KEY to enable scoring";
    $("#ai-label").textContent = "Score with a model";
    $("#ai-status").textContent = "keyword ranking";
  } else {
    $("#ai-label").textContent = `Score with ${provider || "a model"}`;
    $("#ai-status").textContent = provider
      ? `scoring ready — ${provider}` : "scoring ready";
  }
}

async function refreshSystemHealth(sourceData = capabilities) {
  let health;
  try {
    const response = await fetch("/api/system/health");
    if (!response.ok) return;
    health = await response.json();
  } catch {
    return;
  }

  const entries = Object.entries(health.sources || {});
  const good = entries.filter(([, value]) =>
    ["operational", "configured", "direct_api", "web_index_only"].includes(value.status)
  );
  const attention = entries.filter(([, value]) =>
    ["provider_error", "timeout", "network_error", "rate_limited", "missing_credentials",
     "unavailable", "subscription_limited", "limited", "degraded"].includes(value.status)
  );
  $("#system-status-summary").textContent =
    `${good.length} source${good.length === 1 ? "" : "s"} healthy · ` +
    `${attention.length} need${attention.length === 1 ? "s" : ""} attention`;

  const details = $("#status-details");
  details.replaceChildren(
    el("li", null, `${good.length} source${good.length === 1 ? "" : "s"} healthy`),
    ...(attention.length ? [el("li", null,
      `${attention.length} source${attention.length === 1 ? "" : "s"} need attention — expand source details`)] : []),
    el("li", null, health.model?.provider && health.model.provider !== "none"
      ? `Model scoring: ${health.model.provider}` : "Model scoring: keyword ranking"),
    el("li", null, health.storage?.persistent
      ? "Storage: persistent" : "Storage: temporary"),
  );

  // Keep source chips honest after a live provider run. Credential state still
  // controls whether a chip can be selected; health state only adds context.
  const byName = health.sources || {};
  sourceData.sources.forEach((source) => {
    const chip = document.querySelector(`[data-source="${CSS.escape(source.name)}"]`);
    const live = byName[source.name];
    if (!chip || !live) return;
    const status = live.status || "unknown";
    chip.dataset.health = status;
    chip.title = `${source.description || source.name} Live status: ${status}.` +
      (live.error ? ` ${live.error}` : "");
  });
}

// Refresh live health when returning to the workspace; this is intentionally
// low frequency so status checks never compete with an active sweep.
window.setInterval(() => { if (!document.hidden) refreshSystemHealth(); }, 60000);   // a background tab polls nothing

$("#status-toggle").onclick = () => {
  const details = $("#status-details");
  details.hidden = !details.hidden;
  $("#status-toggle").setAttribute("aria-expanded", String(!details.hidden));
};

/* -------------------------------------------------------------- controls */

$("#window").onclick = (e) => {
  const b = e.target.closest("button");
  if (!b) return;
  $("#window").querySelectorAll("button").forEach((x) => {
    x.classList.remove("is-on");
    x.setAttribute("aria-checked", "false");
  });
  b.classList.add("is-on");
  b.setAttribute("aria-checked", "true");
  hours = Number(b.dataset.h);
  saveMonitorPrefs();
};

function radioKeys(group, apply) {
  group.addEventListener("keydown", (e) => {
    if (!["ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown", "Home", "End"].includes(e.key)) return;
    const buttons = [...group.querySelectorAll('[role="radio"]:not([disabled])')];
    const current = buttons.indexOf(document.activeElement);
    let next = current < 0 ? 0 : current;
    if (["ArrowRight", "ArrowDown"].includes(e.key)) next = (next + 1) % buttons.length;
    if (["ArrowLeft", "ArrowUp"].includes(e.key)) next = (next - 1 + buttons.length) % buttons.length;
    if (e.key === "Home") next = 0;
    if (e.key === "End") next = buttons.length - 1;
    e.preventDefault();
    buttons[next].click();
    buttons[next].focus();
    if (apply) apply(buttons[next]);
  });
}
radioKeys($("#window"));

function setSources(mode) {
  const sourceNodes = [...document.querySelectorAll("#sweep-form [data-source]")];
  if (mode === "none") {
    selected = new Set();
  } else if (mode === "all") {
    selected = new Set(sourceNodes.filter((node) => !node.disabled).map((node) => node.dataset.source));
  } else {
    selected = new Set(sourceNodes.filter((node) =>
      !node.disabled && (node.dataset.source === "social_web_index" ||
        capabilities.sources?.find((source) => source.name === node.dataset.source)?.default)
    ).map((node) => node.dataset.source));
  }
  syncSourceChips();
  saveMonitorPrefs();
}

$("#sources-default").onclick = () => setSources("default");
$("#sources-all").onclick = () => setSources("all");
$("#sources-none").onclick = () => setSources("none");

function resetMonitorControls() {
  hours = 72;
  const windowButton = $("#window button[data-h='72']");
  if (windowButton) windowButton.click();
  sweepLimit = 20; maxAi = 8;
  $("#sweep-limit").value = sweepLimit;
  $("#max-ai").value = maxAi;
  $("#fetch-bodies").checked = true;
  $("#use-ai").checked = capabilities.ai_available !== false;
  $("#keep").checked = false;
  setSources("default");
}

$("#sweep-limit").addEventListener("change", () => {
  sweepLimit = Math.max(1, Math.min(250, Number($("#sweep-limit").value) || 20));
  $("#sweep-limit").value = sweepLimit;
  saveMonitorPrefs();
});
$("#max-ai").addEventListener("change", () => {
  maxAi = Math.max(0, Math.min(100, Number($("#max-ai").value) || 0));
  $("#max-ai").value = maxAi;
  saveMonitorPrefs();
});
$("#fetch-bodies").addEventListener("change", saveMonitorPrefs);
$("#use-ai").addEventListener("change", saveMonitorPrefs);
$("#keep").addEventListener("change", saveMonitorPrefs);
$("#reset-controls").onclick = resetMonitorControls;

/* Two tools, one front door. The views are independent — nothing on the
   scamscan side reads watchtower's store and vice versa — so switching sides
   is only ever showing and hiding, never a state handover. */
const VIEWS = ["sweep", "archive", "discover", "queue", "score", "hunt", "campaigns", "huntops"];
const MODE_VIEWS = {
  monitor: ["sweep", "archive"],
  investigate: ["discover", "queue", "score"],
  hunt: ["hunt", "campaigns", "huntops"],
};
const SIDE_MODE = { watchtower: "monitor", scamscan: "investigate", hunter: "hunt" };

function setMode(mode, navigate = true) {
  const views = MODE_VIEWS[mode] || MODE_VIEWS.monitor;
  document.querySelectorAll(".mode-tab").forEach((button) => {
    const active = button.dataset.mode === mode;
    button.classList.toggle("is-on", active);
    button.setAttribute("aria-selected", String(active));
  });
  document.querySelectorAll(".side-group").forEach((group) => {
    group.hidden = !views.includes(group.querySelector(".tab")?.dataset.view);
  });
  const current = document.querySelector(".tab.is-on")?.dataset.view;
  if (!views.includes(current) && navigate) {
    document.querySelector(`.tab[data-view="${views[0]}"]`)?.click();
  } else if (navigate && location.hash !== `#${current}`) {
    location.hash = current;
  }
}

document.querySelectorAll(".mode-tab").forEach((button) => {
  button.addEventListener("click", () => setMode(button.dataset.mode));
});

document.querySelectorAll(".tab").forEach((tab) => {
  tab.onclick = () => {
    setMode(SIDE_MODE[tab.dataset.side] || "monitor", false);
    document.querySelectorAll(".tab").forEach((t) => {
      t.classList.remove("is-on");
      t.removeAttribute("aria-current");
    });
    tab.classList.add("is-on");
    tab.setAttribute("aria-current", "page");
    VIEWS.forEach((v) => {
      const section = document.getElementById(`view-${v}`);
      if (section) section.hidden = tab.dataset.view !== v;
    });
    $("#rail-name").textContent = "MNARA";
    if (location.hash !== `#${tab.dataset.view}`) location.hash = tab.dataset.view;
    const heading = document.querySelector(`#view-${tab.dataset.view} .view-head`);
    if (heading) heading.focus();
    if (tab.dataset.view === "queue") loadQueue();
    if (window.hunterOnView) window.hunterOnView(tab.dataset.view);
  };
});

setMode("monitor", false);

function openHashView() {
  const view = location.hash.slice(1);
  const tab = document.querySelector(`.tab[data-view="${view}"]`);
  if (tab && !tab.classList.contains("is-on")) tab.click();
}
window.addEventListener("hashchange", openHashView);

document.querySelectorAll("[data-open-view]").forEach((button) => {
  button.addEventListener("click", () => {
    document.querySelector(`.tab[data-view="${button.dataset.openView}"]`)?.click();
  });
});

document.querySelectorAll("[data-focus-search]").forEach((button) => {
  button.addEventListener("click", () => {
    $("#sweep-form").scrollIntoView({ behavior: "smooth", block: "center" });
    window.setTimeout(() => $("#q").focus(), 250);
  });
});

/* ----------------------------------------------------------------- sweep */

$("#sweep-form").onsubmit = (e) => {
  e.preventDefault();
  const q = $("#q").value.trim();
  if (q.length < 2) return;
  if (!selected.size) return showEmpty("Pick a source", "Nothing is selected to search.");
  startSweep(q);
};

function startSweep(q) {
  if (stream) stream.close();

  $("#go").disabled = true;
  $("#go").textContent = "Monitoring";
  $("#results").hidden = true;
  $("#empty").hidden = true;
  $("#trace").hidden = false;
  $("#trace-title").textContent = `Monitoring "${q}"`;
  $("#trace-stage").textContent = "";
  previewUrls = new Set();
  $("#findings").replaceChildren();
  $("#summary").replaceChildren();

  const lanes = $("#lanes");
  lanes.replaceChildren();
  const laneOf = {};
  [...selected].forEach((name) => {
    const lane = el("div", "lane pending");
    lane.append(el("span", "lane-name", name));
    const bar = el("div", "lane-bar");
    bar.append(el("div", "lane-fill"));
    lane.append(bar, el("span", "lane-count", "·"));
    lanes.append(lane);
    laneOf[name] = lane;
  });

  const params = new URLSearchParams({
    q, hours,
    sources: [...selected].join(","),
    use_ai: $("#use-ai").checked,
    fetch_bodies: $("#fetch-bodies").checked,
    // Fast interactive default is limit: 20; users can raise it in Result
    // budget without needing to leave the web application.
    limit: sweepLimit,
    // Model calls are serial and each can take seconds. Eight is the default;
    // the control lets investigators trade explanation depth for latency.
    max_ai: maxAi,
    // Off by default, same as the API. The Archive tab is empty until this is
    // ticked, so it's the only way to populate it from the browser.
    save: $("#keep").checked,
  });

  stream = new EventSource(`/api/sweep?${params}`);

  stream.addEventListener("source", (ev) => {
    const d = JSON.parse(ev.data);
    const lane = laneOf[d.name];
    if (!lane) return;
    lane.classList.remove("pending");
    lane.classList.add("done");
    if (d.error) lane.classList.add("failed");
    if (d.skipped) lane.classList.add("skipped");
    if (!d.count) lane.classList.add("zero");
    // Bars are relative to 20 hits, capped — absolute scale would make a
    // 3-hit source look like a failure next to a 60-hit one.
    lane.style.setProperty("--w", `${Math.min(100, (d.count / 20) * 100) || 4}%`);
    // A failed or unsearched lane must never read as "0". Zero is a finding.
    lane.querySelector(".lane-count").textContent =
      d.error ? "failed" : d.skipped ? "off" : d.count;
    if (d.reason || d.skipped) lane.title = d.reason || d.skipped;
    showPreviews(d.preview || []);
  });

  stream.addEventListener("stage", (ev) => {
    const d = JSON.parse(ev.data);
    const label = {
      dedupe: `deduped ${d.before} → ${d.after}`,
      fetch: `reading ${d.count} article${d.count === 1 ? "" : "s"}`,
      score: `scoring ${d.count}`,
    }[d.stage];
    if (label) $("#trace-stage").textContent = label;
  });

  stream.addEventListener("scored", (ev) => {
    const d = JSON.parse(ev.data);
    $("#trace-stage").textContent = `scored [${d.relevance}] ${d.title}`;
  });

  stream.addEventListener("done", (ev) => {
    finish();
    render(JSON.parse(ev.data));
  });

  stream.addEventListener("failed", (ev) => {
    finish();
    showEmpty("The sweep stopped", JSON.parse(ev.data).message);
  });

  stream.onerror = () => {
    if (!$("#go").disabled) return;   // already finished cleanly
    finish();
    showEmpty("Lost the connection", "The server closed the stream. Check its log and try again.");
  };
}

function finish() {
  if (stream) { stream.close(); stream = null; }
  $("#go").disabled = false;
  $("#go").textContent = "Monitor";
  $("#trace-stage").textContent = "";
  $("#trace-title").textContent = "Sources";
}

function showPreviews(items) {
  const fresh = items.filter((item) => item.url && !previewUrls.has(item.url));
  if (!fresh.length) return;
  fresh.forEach((item) => previewUrls.add(item.url));
  $("#results").hidden = false;
  $("#empty").hidden = true;
  const summary = $("#summary");
  if (!summary.querySelector(".live-preview")) {
    summary.replaceChildren(el(
      "span", "warn live-preview",
      "Live findings · provisional keyword ratings while remaining sources finish"
    ));
  }
  fresh.forEach((item) => $("#findings").append(card(item)));
}

$("#cancel-sweep").onclick = () => {
  if (!stream) return;
  stream.close();
  stream = null;
  finish();
  showEmpty("Updates stopped", "The browser stopped listening. Requests already sent to providers may still finish or incur cost.");
};

/* --------------------------------------------------------------- render */

function gauge(band) {
  const g = el("span", "gauge");
  const on = BAND_SEGMENTS[band] || 1;
  for (let i = 0; i < 5; i++) g.append(el("i", i < on ? "on" : ""));
  return g;
}

function card(item) {
  const c = el("article", "card");
  c.style.setProperty("--band", BAND_COLOUR[item.band] || "var(--weak)");

  const top = el("div", "card-top");
  top.append(gauge(item.band), el("span", "score", item.relevance));
  if (item.provisional) {
    const provisional = el("span", "flag", "provisional");
    provisional.title = "Fast keyword rating; final rating may change after analysis.";
    top.append(provisional);
  }
  c.append(top);

  const h = el("h3");
  const a = el("a", null, item.title || "(untitled)");
  a.href = safeHref(item.url);
  a.target = "_blank";
  a.rel = "noopener noreferrer";
  h.append(a);
  c.append(h);

  // How many independent domains carried this story. The cheapest strong
  // signal that something is real, and it would otherwise be thrown away by
  // dedupe — so it gets its own badge rather than hiding in the metadata line.
  const corroboration = item.raw_meta?.corroboration || 1;
  if (corroboration > 1) {
    const c = el("span", "corrob", `${corroboration} sources`);
    c.title = (item.raw_meta.corroborating_domains || []).join("\n");
    top.append(c);
  }
  if (item.raw_meta?.headline_only) {
    const h = el("span", "flag", "headline only");
    h.title = "No article body was read — scored on the headline alone.";
    top.append(h);
  }

  const meta = el("p", "card-meta");
  meta.append(el("span", null, item.source));
  if (item.published_at) meta.append(el("span", null, item.published_at.slice(0, 16)));
  if (item.author) meta.append(el("span", null, item.author));
  try { meta.append(el("span", null, new URL(item.url).hostname)); } catch {}
  c.append(meta);

  const body = item.summary || item.text;
  if (body) c.append(el("p", "body", body.slice(0, 320)));

  if (item.categories?.length) {
    const tags = el("div", "tags");
    item.categories.forEach((t) => tags.append(el("span", "tag", t)));
    c.append(tags);
  }
  return c;
}

/* Why a count can't be trusted, in the user's words rather than a stack trace. */
function coverageNotes(d) {
  return [
    ...Object.entries(d.failed || {}).map(([k, v]) => `${k} failed — ${v}`),
    ...Object.entries(d.skipped || {}).map(([k, v]) => `${k} was not searched — ${v}`),
  ];
}

function render(d) {
  const notes = coverageNotes(d);

  if (!d.items.length) {
    // "Nothing came back" is a claim about the world. Only make it when every
    // source actually answered; otherwise this is an absence of evidence that
    // someone could mistake for evidence of absence.
    return d.complete === false
      ? showEmpty(
          "Incomplete sweep — no results",
          "This is not a clean result. Some sources could not be searched, so " +
          "nothing here rules anything out.",
          notes)
      : showEmpty(
          "Nothing came back",
          "Every source was searched and none returned a match. Try a longer " +
          "window, fewer words, or looser terms.",
          notes);
  }

  const strong = d.items.filter((i) => i.relevance >= 60).length;
  const sum = $("#summary");
  sum.replaceChildren();
  // Results arrived, but not from everywhere. Say so next to the count, or the
  // count reads as the whole picture.
  if (d.complete === false) {
    const w = el("span", "warn",
      `partial coverage — ${notes.length} source${notes.length === 1 ? "" : "s"} unavailable`);
    w.title = notes.join("\n");
    sum.append(w);
  }
  const n = el("span");
  n.innerHTML = `<strong>${d.items.length}</strong> result${d.items.length === 1 ? "" : "s"}`;
  sum.append(n);
  if (d.enriched) {
    const s = el("span");
    s.innerHTML = `<strong>${strong}</strong> scored 60+`;
    sum.append(s);
  } else {
    sum.append(el("span", null,
      `keyword ranking — ${d.scoring_error || "no API key"}`));
  }
  if (d.report) {
    const links = el("span", "report-links");
    const markdownLink = el("a", null, "Markdown");
    markdownLink.href = `/api/report/${encodeURIComponent(d.report)}`;
    links.append(markdownLink);
    if (d.report_html) {
      const htmlLink = el("a", null, "Cyberpunk HTML / PDF");
      htmlLink.href = `/api/report/${encodeURIComponent(d.report_html)}`;
      htmlLink.target = "_blank";
      htmlLink.rel = "noopener";
      htmlLink.title = "Open the styled report, then use Print → Save as PDF";
      links.append(htmlLink);
    }
    sum.append(links);
  }

  $("#findings").replaceChildren(...d.items.map(card));

  const side = $("#side");
  side.replaceChildren();

  if (d.entities.length) {
    const p = el("div", "panel");
    p.append(el("h4", null, "Recurring names"));
    const ul = el("ul");
    d.entities.slice(0, 12).forEach((e) => {
      const li = el("li");
      li.append(el("span", null, e.name), el("span", null, e.count));
      ul.append(li);
    });
    p.append(ul);
    side.append(p);
  }

  const p2 = el("div", "panel");
  p2.append(el("h4", null, "Source yield"));
  const ul2 = el("ul");
  Object.entries(d.per_source).forEach(([k, v]) => {
    const li = el("li");
    li.append(el("span", null, k), el("span", null, v));
    ul2.append(li);
  });
  p2.append(ul2);
  side.append(p2);

  if (d.errors.length) {
    const p3 = el("div", "panel");
    p3.append(el("h4", null, "Problems"));
    d.errors.slice(0, 6).forEach((e) => p3.append(el("p", "errs", e)));
    side.append(p3);
  }

  $("#results").hidden = false;
  $("#empty").hidden = true;
}

function showEmpty(title, msg, errors) {
  const box = $("#empty");
  box.replaceChildren(el("h3", null, title), el("p", null, msg));
  // A zero-result sweep is more often a broken source than an absent story.
  // The Problems panel lives in #results, which this hides — so without this
  // the reason a source failed is only ever in the server log.
  if (errors && errors.length) {
    const box2 = el("div", "empty-errs");
    box2.append(el("h4", null, "What went wrong"));
    errors.slice(0, 6).forEach((e) => box2.append(el("p", "errs", e)));
    box.append(box2);
  }
  box.hidden = false;
  $("#results").hidden = true;
}

/* --------------------------------------------------------------- archive */

$("#archive-form").onsubmit = async (e) => {
  e.preventDefault();
  const q = $("#aq").value.trim();
  if (!q) return;
  const out = $("#archive-results");
  out.replaceChildren(el("p", "hint", "Searching…"));
  try {
    const r = await fetch(`/api/archive?q=${encodeURIComponent(q)}`);
    if (!r.ok) {
      const err = await r.json();
      out.replaceChildren(el("p", "errs", err.detail || "Search failed"));
      return;
    }
    const d = await r.json();
    out.replaceChildren(
      ...(d.items.length
        ? d.items.map(card)
        : [el("p", "hint", "Nothing saved matches that. Turn on “Keep results” in Monitor to start filling saved results.")])
    );
  } catch {
    out.replaceChildren(el("p", "errs", "Could not reach the server."));
  }
};

/* ======================================================================
   scamscan — the other side. Separate store, separate config, separate
   failure modes: here an empty queue reads as "this brand is clean", so a
   query that never ran must never look like a query that found nothing.
   ====================================================================== */

let scam = {};
let minScore = 45;
let disposition = "new";
let huntStream = null;

async function initScamscan() {
  let d;
  try {
    const response = await fetch("/api/scamscan/status");
    d = await response.json();
  } catch {
    $("#hunt-go").disabled = true;
    $("#dry-run-hunt").disabled = true;
    $("#hunt-cost").textContent = "Investigation status is unavailable; planning and hunts are disabled until the server responds.";
    $("#hunt-cost").hidden = false;
    return;
  }
  if (d.detail) {
    $("#hunt-go").disabled = true;
    $("#dry-run-hunt").disabled = true;
    $("#hunt-cost").textContent = d.detail;
    $("#hunt-cost").hidden = false;
    return;
  }
  scam = d;
  $("#brand-name").textContent = d.brand;

  const perTopic = (d.queries_per_topic || 0) * (d.max_uses_per_query || 0);
  const notes = [
    `Up to ${perTopic} searches per topic (about $${(perTopic * 0.01).toFixed(2)}) ` +
    `plus tokens, on ${d.model} with ${d.search_tool}.`,
  ];
  if (!d.api_available) {
    $("#hunt-go").disabled = true;
    $("#dry-run-hunt").disabled = true;
    $("#hunt-go").title = "Set ANTHROPIC_API_KEY to run a hunt";
    notes.push("No ANTHROPIC_API_KEY is set, so a hunt cannot run. Scoring on the Score tab still works — it makes no API calls.");
  }
  // A review queue on ephemeral storage is worse than no queue: the analyst
  // verdicts are the whole point and they are what gets lost.
  if (d.ephemeral_storage) {
    notes.push("Storage on this host is temporary — findings and the verdicts you record on them are lost between requests.");
    $("#hunt-go").disabled = true;
    $("#hunt-go").title = "Hunts require durable storage so findings and verdicts are not lost";
  }
  $("#hunt-cost").textContent = notes.join(" ");
  $("#hunt-cost").hidden = false;
}

/* --------------------------------------------------------- queue filters */

function segmented(id, attr, apply) {
  $(id).onclick = (e) => {
    const b = e.target.closest("button");
    if (!b) return;
    $(id).querySelectorAll("button").forEach((x) => {
      x.classList.remove("is-on");
      x.setAttribute("aria-checked", "false");
    });
    b.classList.add("is-on");
    b.setAttribute("aria-checked", "true");
    apply(b.dataset[attr]);
    loadQueue();
  };
  radioKeys($(id));
}
segmented("#min-score", "s", (v) => { minScore = Number(v); });
segmented("#disposition", "d", (v) => { disposition = v; });

$("#queue-form").onsubmit = (e) => { e.preventDefault(); loadQueue(); };

async function loadQueue() {
  const out = $("#queue-results");
  out.replaceChildren(el("p", "hint", "Loading…"));
  try {
    const r = await fetch(
      `/api/scamscan/queue?min_score=${minScore}&disposition=${disposition}`);
    if (!r.ok) {
      const err = await r.json();
      out.replaceChildren(el("p", "errs", err.detail || "Could not read the queue."));
      return;
    }
    const d = await r.json();
    if (!d.items.length) {
      // Never let this read as "the brand is clean". It means this database is
      // empty, which is a fact about the tool, not about the world.
      const box = el("div", "empty-inline");
      box.append(
        el("h3", null, "Nothing in the queue"),
        el("p", null,
          `No stored finding scores ${minScore}+ with disposition "${disposition}". ` +
          "That is a statement about this database, not about the brand — run a " +
          "hunt above, or widen the filters."));
      out.replaceChildren(box);
      return;
    }
    out.replaceChildren(...d.items.map(queueCard));
  } catch {
    out.replaceChildren(el("p", "errs", "Could not reach the server."));
  }
}

/* ---------------------------------------------------------- queue render */

/* Every family that reported, as a bar. Absent families are omitted rather
   than drawn at zero — an absent model_confidence is not a low one, and the
   chart has to say the same thing the scorer does. */
function familyBars(b) {
  const box = el("div", "fams");
  const rows = [
    ["lexicon", b.lexicon_score], ["artifact", b.artifact_score],
    ["impersonation", b.impersonation_score], ["model", b.model_score],
  ];
  rows.forEach(([name, value]) => {
    const row = el("div", "fam");
    row.append(el("span", "fam-name", name));
    const bar = el("div", "fam-bar");
    if (value == null) {
      // No fill element at all. A .fam-fill with no width set is a block that
      // fills its track, which drew an absent family as a full bar — the one
      // reading this must never produce.
      row.classList.add("absent");
      row.append(bar, el("span", "fam-val", "absent"));
    } else {
      const fill = el("div", "fam-fill");
      fill.style.width = `${Math.max(2, Math.min(100, value))}%`;
      bar.append(fill);
      row.append(bar, el("span", "fam-val", String(Math.round(value))));
    }
    box.append(row);
  });
  return box;
}

/* Each hit with the source it came from. A score you cannot trace is a score
   you cannot defend, so the provenance is on the card, not in a log. */
function hitList(hits) {
  const box = el("div", "hits");
  (hits || []).slice(0, 14).forEach((h) => {
    const m = /^(.*?)\s*\[(.+)\]$/.exec(h);
    const chip = el("span", h.startsWith("counter:") ? "hit is-counter" : "hit");
    chip.append(el("span", "hit-term", m ? m[1] : h));
    if (m) chip.append(el("span", "hit-src", m[2]));
    box.append(chip);
  });
  return box;
}

/* ------------------------------------------------------------- discover */

$("#discover-form").onsubmit = async (e) => {
  e.preventDefault();
  const brand = $("#discover-brand").value.trim();
  const limit = Math.max(1, Math.min(20, Number($("#discover-limit").value) || 10));
  const button = $("#discover-go");
  const trace = $("#discover-trace");
  const stage = $("#discover-stage");
  const out = $("#discover-results");

  button.disabled = true;
  button.textContent = "Searching";
  trace.hidden = false;
  stage.textContent = `looking for ${brand}`;
  $("#discover-summary").replaceChildren();
  out.replaceChildren();

  try {
    const r = await fetch("/api/investigations", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ brand, query: $("#discover-query").value.trim() || brand, limit }),
    });
    const d = await r.json();
    if (!r.ok) {
      out.replaceChildren(el("p", "errs", d.detail || "Discovery could not run."));
      stage.textContent = "incomplete";
      return;
    }

    const candidates = d.candidates || [];
    stage.textContent = `${candidates.length} domain${candidates.length === 1 ? "" : "s"}`;
    const summary = $("#discover-summary");
    summary.append(el("span", null,
      `${candidates.length} domains · ${d.counts?.social_account || 0} social accounts · ` +
      `${d.counts?.phone_number || 0} phones`));
    if (d.filtered_low_signal) {
      const filtered = el("span", null,
        `${d.filtered_low_signal} low-signal domain${d.filtered_low_signal === 1 ? "" : "s"} filtered`);
      filtered.title = "Search matches without enough brand, credential, payment, threat, or infrastructure evidence.";
      summary.append(filtered);
    }
    summary.append(el("span", "warn", d.zero_key_mode ? "zero-key OSINT mode" : "review before acting"));
    const runRecord = el("button", "summary-action", "View run record");
    runRecord.type = "button";
    runRecord.addEventListener("click", () => openInvestigationDetail(d.id));
    summary.append(runRecord);
    renderInvestigationCoverage(d.coverage || {});
    renderInvestigationExpansion(d.expansion || {});
    renderCampaigns(d.campaigns || []);
    await renderInvestigationGraph(d.id);
    if (!candidates.length) {
      const empty = el("div", "empty-inline");
      empty.append(el("h3", null, "No candidates returned"),
        el("p", null, "This only describes this search run; it does not establish that the brand is clean."));
      out.replaceChildren(empty);
    } else {
      out.replaceChildren(...candidates.sort((a, b) => b.risk_score - a.risk_score).map(investigationCard));
    }
  } catch {
    stage.textContent = "incomplete";
    out.replaceChildren(el("p", "errs", "Could not reach the discovery service."));
  } finally {
    button.disabled = false;
    button.textContent = "Find sites";
  }
};

function renderInvestigationCoverage(coverage) {
  const box = $("#discover-coverage");
  const failed = [...(coverage.failed || []), ...(coverage.unavailable || []), ...(coverage.limited || [])];
  box.replaceChildren(el("h3", null, "Source coverage"),
    el("p", null, `${coverage.successful?.length || 0} successful of ${coverage.configured || 0} configured`),
    el("p", "hint", coverage.statement || "Coverage is limited to accessible sources."));
  const tags = el("div", "tags");
  (coverage.successful || []).forEach(name => tags.append(el("span", "tag", `✓ ${name}`)));
  failed.forEach(item => tags.append(el("span", "tag warn", `✗ ${item.provider || item.source}: ${item.status}`)));
  box.append(tags);
}

function renderInvestigationExpansion(expansion) {
  const box = $("#discover-expansion");
  if (!expansion || (!expansion.rounds?.length && !expansion.provider_calls)) {
    box.replaceChildren();
    return;
  }
  const rounds = (expansion.rounds || []).map((round) =>
    `${round.depth}: ${round.pivots} pivot${round.pivots === 1 ? "" : "s"}, ` +
    `${round.new_domains} new domain${round.new_domains === 1 ? "" : "s"}, ` +
    `${round.inspected} inspected`
  ).join(" · ");
  box.replaceChildren(...[
    el("h3", null, "Discovery expansion"),
    el("p", null, `${expansion.domains_discovered || 0} candidate domains · ` +
      `${expansion.domains_inspected || 0} pages inspected · ` +
      `${expansion.pivot_entities || 0} pivot entities`),
    rounds ? el("p", "hint", `Rounds — ${rounds}`) : null,
    el("p", "hint", `Provider calls ${expansion.provider_calls || 0}/${expansion.provider_budget || 0} · ` +
      `${expansion.termination_reason || "bounded run complete"}`),
  ].filter(Boolean));
}

function renderCampaigns(campaigns) {
  const box = $("#discover-campaigns");
  if (!campaigns.length) { box.replaceChildren(); return; }
  box.replaceChildren(el("h3", null, "Correlated campaigns"));
  campaigns.forEach(item => {
    const row = el("button", "campaign-row");
    row.type = "button";
    row.textContent = `${item.public_id} · ${item.correlation_label} correlation · risk ${Math.round(item.threat_score || 0)}`;
    row.addEventListener("click", () => openCampaignDetail(item.id));
    box.append(row);
  });
}

async function renderInvestigationGraph(id) {
  const box = $("#discover-graph");
  box.replaceChildren();
  if (!id) return;
  const response = await fetch(`/api/investigations/${encodeURIComponent(id)}/graph`);
  if (!response.ok) return;
  const graph = await response.json();
  box.append(el("h3", null, `Entity graph · ${graph.nodes.length} nodes · ${graph.edges.length} edges`));
  const nodes = el("div", "graph-nodes");
  graph.nodes.slice(0, 40).forEach(node => {
    const button = el("button", `graph-node type-${node.entity_type}`,
      `${node.entity_type}: ${node.display_value}`);
    button.type = "button";
    button.addEventListener("click", () => openEntityDetail(node.id));
    nodes.append(button);
  });
  box.append(nodes);
  const edges = el("div", "graph-edges");
  graph.edges.slice(0, 30).forEach(edge => edges.append(el("p", null,
    `${edge.relationship_type} · ${edge.observed_value || "evidence"} · ${edge.source}`)));
  box.append(edges);
}

function investigationCard(item) {
  const c = el("article", "card");
  const score = item.risk_score || 0;
  const band = score >= 70 ? "HIGH" : score >= 45 ? "MED" : score >= 20 ? "LOW" : "WEAK";
  c.style.setProperty("--band", BAND_COLOUR[band]);
  const top = el("div", "card-top");
  top.append(gauge(band), el("span", "score", Math.round(score)),
    el("span", "flag", item.machine_verdict || "INSUFFICIENT_EVIDENCE"));
  c.append(top);
  const title = el("h3");
  const link = el("a", null, item.domain); link.href = safeHref(item.url); link.target = "_blank";
  link.rel = "noopener noreferrer"; title.append(link); c.append(title);
  c.append(el("p", "card-meta", `${Math.round((item.confidence || 0) * 100)}% confidence · ` +
    `${item.evidence_count || 0} direct evidence records`));
  const reasons = el("ol", "evidence-reasons");
  (item.strongest_evidence || []).forEach(reason => reasons.append(el("li", null, reason)));
  if (reasons.childNodes.length) c.append(el("h4", null, "Why Mnara flagged this"), reasons);
  if (item.contradictory_evidence?.length) {
    c.append(el("p", "reason", `Contradictory evidence: ${item.contradictory_evidence.join("; ")}`));
  }
  const sources = el("div", "tags");
  (item.sources || []).forEach(source => sources.append(el("span", "tag", source)));
  c.append(sources);
  if (item.entity_id) {
    const inspect = el("button", "inspect-button", "Inspect evidence");
    inspect.type = "button";
    inspect.addEventListener("click", () => openEntityDetail(item.entity_id));
    c.append(inspect);
  }
  return c;
}

const detailDialog = $("#detail-dialog");
$("#detail-close").addEventListener("click", () => detailDialog.close());
detailDialog.addEventListener("click", (event) => {
  if (event.target === detailDialog) detailDialog.close();
});

function showDetail(kind, title, content) {
  $("#detail-kind").textContent = kind;
  $("#detail-title").textContent = title;
  $("#detail-body").replaceChildren(content);
  if (!detailDialog.open) detailDialog.showModal();
}

async function openEntityDetail(id) {
  const loading = el("p", "hint", "Loading entity and evidence…");
  showDetail("Entity evidence", "Loading…", loading);
  try {
    const [entityResponse, evidenceResponse] = await Promise.all([
      fetch(`/api/entities/${encodeURIComponent(id)}`),
      fetch(`/api/entities/${encodeURIComponent(id)}/evidence`),
    ]);
    if (!entityResponse.ok || !evidenceResponse.ok) throw new Error();
    const entity = await entityResponse.json();
    const evidence = (await evidenceResponse.json()).evidence || [];
    const body = el("div", "detail-content");
    const facts = el("dl", "detail-facts");
    [["Type", entity.entity_type], ["Canonical value", entity.canonical_value],
      ["Confidence", `${Math.round((entity.confidence || 0) * 100)}%`],
      ["Last observed", entity.last_seen || "Unknown"]].forEach(([name, value]) => {
        facts.append(el("dt", null, name), el("dd", null, value));
      });
    body.append(facts, el("h3", null, `Evidence records (${evidence.length})`));
    const list = el("div", "evidence-list");
    if (!evidence.length) list.append(el("p", "hint", "No direct evidence is stored for this entity."));
    evidence.forEach((item) => {
      const record = el("article", "evidence-record");
      record.append(el("strong", null, item.evidence_type),
        el("span", "tag", item.source), el("p", null, item.observed_value || "Observed"));
      if (item.source_url) {
        const link = el("a", null, "Open source");
        link.href = safeHref(item.source_url); link.target = "_blank"; link.rel = "noopener noreferrer";
        record.append(link);
      }
      list.append(record);
    });
    body.append(list);
    if (!capabilities.ephemeral_storage) body.append(entityVerdictForm(id));
    else body.append(el("p", "warn-note", "Verdicts require durable storage on this deployment."));
    showDetail("Entity evidence", entity.display_value || entity.canonical_value, body);
  } catch {
    showDetail("Entity evidence", "Could not load entity",
      el("p", "errs", "The entity or its evidence is no longer available. Close this panel and rerun the investigation."));
  }
}

function entityVerdictForm(id) {
  const form = el("form", "entity-verdict-form");
  const heading = el("h3", null, "Record analyst verdict");
  const label = el("label", "field-label", "Verdict");
  const select = el("select", "detail-select");
  const selectId = `entity-verdict-${id}`;
  select.id = selectId;
  label.htmlFor = selectId;
  select.required = true;
  ["needs_review", "confirmed_malicious", "likely_malicious", "suspicious", "monitor",
    "legitimate", "benign", "false_positive", "duplicate"].forEach((value) => {
      const option = el("option", null, value.replaceAll("_", " "));
      option.value = value; select.append(option);
    });
  const commentLabel = el("label", "field-label", "Analyst comment");
  const comment = el("textarea", "detail-comment");
  const commentId = `entity-comment-${id}`;
  comment.id = commentId;
  commentLabel.htmlFor = commentId;
  comment.rows = 3; comment.maxLength = 2000;
  const submit = el("button", "primary-button", "Save verdict");
  submit.type = "submit";
  const feedback = el("p", "form-feedback");
  feedback.setAttribute("aria-live", "polite");
  form.append(heading, label, select, commentLabel, comment, submit, feedback);
  form.addEventListener("submit", async (event) => {
    event.preventDefault(); submit.disabled = true; submit.textContent = "Saving…";
    try {
      const response = await fetch(`/api/entities/${encodeURIComponent(id)}/verdict`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ verdict: select.value, comment: comment.value, analyst_identifier: "web-analyst" }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || "Verdict was rejected");
      feedback.className = "form-feedback success";
      feedback.textContent = `Saved as ${data.analyst_verdict.replaceAll("_", " ")}. System classification remains unchanged.`;
    } catch (error) {
      feedback.className = "form-feedback errs";
      feedback.textContent = error.message || "Verdict was not saved.";
    } finally { submit.disabled = false; submit.textContent = "Save verdict"; }
  });
  return form;
}

async function openCampaignDetail(id) {
  showDetail("Correlated campaign", "Loading…", el("p", "hint", "Loading campaign entities…"));
  try {
    const response = await fetch(`/api/campaigns/${encodeURIComponent(id)}`);
    if (!response.ok) throw new Error();
    const campaign = await response.json();
    const body = el("div", "detail-content");
    const summary = el("p", "campaign-summary",
      `${campaign.correlation_label} correlation · threat score ${Math.round(campaign.threat_score || 0)} · ${campaign.status}`);
    const list = el("div", "campaign-entities");
    (campaign.entities || []).forEach((entity) => {
      const button = el("button", "entity-row");
      button.type = "button";
      button.append(el("span", null, entity.display_value || entity.canonical_value),
        el("small", null, `${entity.entity_type} · ${Math.round((entity.relationship_strength || 0) * 100)}% link`));
      button.addEventListener("click", () => openEntityDetail(entity.id));
      list.append(button);
    });
    body.append(summary, list);
    showDetail("Correlated campaign", campaign.public_id, body);
  } catch {
    showDetail("Correlated campaign", "Could not load campaign",
      el("p", "errs", "Campaign details are unavailable. Rerun the investigation and try again."));
  }
}

async function openInvestigationDetail(id) {
  showDetail("Investigation record", "Loading…", el("p", "hint", "Loading source run record…"));
  try {
    const response = await fetch(`/api/investigations/${encodeURIComponent(id)}`);
    if (!response.ok) throw new Error();
    const run = await response.json();
    const body = el("div", "detail-content");
    const facts = el("dl", "detail-facts");
    [["Status", run.status], ["Query", run.query],
      ["Coverage", `${run.coverage_percentage || 0}%`], ["Started", run.started_at || "Unknown"]]
      .forEach(([name, value]) => facts.append(el("dt", null, name), el("dd", null, value)));
    body.append(facts, el("h3", null, "Provider runs"));
    const list = el("div", "source-run-list");
    (run.source_runs || []).forEach((source) => {
      const row = el("article", `source-run status-${source.status}`);
      row.append(el("strong", null, source.source), el("span", "tag", source.status),
        el("p", null, source.error_message || `${source.results_returned || 0} results returned`));
      list.append(row);
    });
    body.append(list);
    showDetail("Investigation record", run.brand, body);
  } catch {
    showDetail("Investigation record", "Could not load run",
      el("p", "errs", "This investigation record is unavailable. Rerun discovery to create a new record."));
  }
}

function discoveryCard(item) {
  const c = el("article", "card");
  const band = item.score >= 80 ? "HIGH" : item.score >= 45 ? "MED"
    : item.score >= 20 ? "LOW" : "WEAK";
  c.style.setProperty("--band", BAND_COLOUR[band]);

  const top = el("div", "card-top");
  top.append(gauge(band), el("span", "score", Math.round(item.score || 0)),
    el("span", "flag", item.classification || "candidate"));
  c.append(top);

  const h = el("h3");
  const a = el("a", null, item.title || item.url || "(untitled candidate)");
  a.href = safeHref(item.url);
  a.target = "_blank";
  a.rel = "noopener noreferrer";
  h.append(a);
  c.append(h);

  const meta = el("p", "card-meta");
  meta.append(el("span", null, item.brand || "brand"),
    el("span", null, item.source || "search"));
  try { meta.append(el("span", null, new URL(item.url).hostname)); } catch {}
  c.append(meta);
  if (item.summary) c.append(el("p", "body", item.summary.slice(0, 320)));

  const b = item.breakdown || {};
  c.append(familyBars(b));
  if (b.lexicon_hits?.length) c.append(hitList(b.lexicon_hits));
  if (b.impersonation_reason) {
    c.append(el("p", "reason", `host: ${b.impersonation_reason}`));
  }
  c.append(el("p", "candidate-note",
    "Candidate only — confirm against the live page and independent evidence."));
  return c;
}

function queueCard(item) {
  const c = el("article", "card");
  c.style.setProperty("--band", BAND_COLOUR[item.band] || "var(--weak)");

  const top = el("div", "card-top");
  top.append(gauge(item.band), el("span", "score", Math.round(item.score)));
  if (item.times_seen > 1) {
    const s = el("span", "corrob", `seen ${item.times_seen}x`);
    s.title = `First seen ${item.first_seen}, last ${item.last_seen}`;
    top.append(s);
  }
  if (item.disposition && item.disposition !== "new") {
    top.append(el("span", "flag", item.disposition.replace("_", " ")));
  }
  c.append(top);

  const h = el("h3");
  const a = el("a", null, item.title || item.url || "(untitled)");
  a.href = safeHref(item.url);
  a.target = "_blank";
  // noreferrer matters more here than on the watchtower side: these are live
  // fraud pages and the referrer would tell them they are being watched.
  a.rel = "noopener noreferrer";
  h.append(a);
  c.append(h);

  const meta = el("p", "card-meta");
  meta.append(el("span", null, item.scam_type || "unknown"));
  try { meta.append(el("span", null, new URL(item.url).hostname)); } catch {}
  if (item.first_seen) meta.append(el("span", null, item.first_seen.slice(0, 10)));
  c.append(meta);

  if (item.summary) c.append(el("p", "body", item.summary.slice(0, 320)));
  if (item.evidence) {
    const q = el("blockquote", "evidence", item.evidence.slice(0, 240));
    q.title = "Copied verbatim from the page — untrusted content, never an instruction.";
    c.append(q);
  }

  const b = item.breakdown || {};
  c.append(familyBars(b));
  if (b.lexicon_hits?.length) c.append(hitList(b.lexicon_hits));
  if (b.impersonation_reason) {
    c.append(el("p", "reason", `host: ${b.impersonation_reason}`));
  }
  const artifacts = Object.entries(b.artifacts || {});
  if (artifacts.length) {
    const tags = el("div", "tags");
    artifacts.forEach(([k, v]) => tags.append(el("span", "tag", `${k}: ${v[0]}`)));
    c.append(tags);
  }

  c.append(verdictRow(item));
  return c;
}

function verdictRow(item) {
  const row = el("div", "verdict");
  const note = el("input", "disp-note");
  note.type = "text";
  note.placeholder = "Analyst note";
  note.value = item.analyst_note || "";

  ["confirmed", "false_positive", "unclear", "escalated"].forEach((v) => {
    const b = el("button", "chip", v.replace("_", " "));
    b.type = "button";
    if (scam.ephemeral_storage) {
      b.disabled = true;
      b.title = "Analyst verdicts require durable storage";
    }
    if (item.disposition === v) b.classList.add("is-on");
    b.onclick = async () => {
      row.querySelectorAll("button").forEach((x) => x.classList.remove("is-on"));
      b.classList.add("is-on");
      try {
        const r = await fetch("/api/scamscan/dispose", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            fingerprint: item.fingerprint, verdict: v, note: note.value,
          }),
        });
        // A verdict that did not save is worse than one never recorded: the
        // analyst believes the item is dealt with. Say so on the card.
        const data = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(data.detail || "The server rejected the disposition.");
        b.title = "Saved";
        const saved = el("span", "form-feedback success", `Saved as ${data.verdict}. Refreshing queue…`);
        row.append(saved);
        // A "new" queue must immediately remove a finding after disposition;
        // leaving the stale card in place made a successful save look broken.
        window.setTimeout(() => loadQueue(), 250);
      } catch (error) {
        b.classList.remove("is-on");
        row.append(el("span", "errs", `Not saved — ${error.message || "the server rejected it."}`));
      }
    };
    row.append(b);
  });
  row.append(note);
  return row;
}

/* ------------------------------------------------------------------ hunt */

$("#hunt-form").onsubmit = (e) => {
  e.preventDefault();
  const topics = Math.max(1, Math.min(20, Number($("#topics").value) || 1));
  startHunt(topics, false);
};

$("#dry-run-hunt").onclick = () => {
  const topics = Math.max(1, Math.min(20, Number($("#topics").value) || 1));
  startHunt(topics, true);
};

function logLine(cls, text, title) {
  const line = el("div", cls, text);
  if (title) line.title = title;
  $("#hunt-log").append(line);
  $("#hunt-log").scrollTop = $("#hunt-log").scrollHeight;
}

function startHunt(topics, dryRun = false) {
  if (huntStream) huntStream.close();
  $("#hunt-go").disabled = true;
  $("#dry-run-hunt").disabled = true;
  $("#hunt-go").textContent = dryRun ? "Planning" : "Hunting";
  $("#hunt-trace").hidden = false;
  $("#hunt-title").textContent = `${dryRun ? "Planning" : "Hunting"} ${topics} topic${topics === 1 ? "" : "s"}`;
  $("#hunt-stage").textContent = "";
  $("#hunt-log").replaceChildren();

  huntStream = new EventSource(`/api/scamscan/hunt?topics=${topics}&dry_run=${dryRun}`);

  huntStream.addEventListener("start", (ev) => {
    const d = JSON.parse(ev.data);
    $("#hunt-stage").textContent =
      `${d.model} · ${d.tool} · structured ${d.structured ? "on" : "off"}`;
  });
  huntStream.addEventListener("topic", (ev) => {
    logLine("log-topic", JSON.parse(ev.data).topic);
  });
  huntStream.addEventListener("query", (ev) => {
    logLine("log-query", JSON.parse(ev.data).query);
  });
  huntStream.addEventListener("finding", (ev) => {
    const d = JSON.parse(ev.data);
    logLine("log-find",
      `${d.new ? "NEW" : "dup"} ${Math.round(d.score)}  ${d.url.slice(0, 68)}`,
      d.title);
  });
  huntStream.addEventListener("note", (ev) => {
    logLine("log-note", JSON.parse(ev.data).message);
  });
  // A query that could not be searched is not a query that found nothing.
  // It gets its own colour so it can never be read as a clean result.
  huntStream.addEventListener("unsearched", (ev) => {
    const d = JSON.parse(ev.data);
    logLine("log-fail", `NOT SEARCHED: ${d.query || d.topic} — ${d.reason}`);
  });
  huntStream.addEventListener("done", (ev) => {
    finishHunt();
    const summary = JSON.parse(ev.data);
    huntSummary(summary);
    if (!summary.dry_run) loadQueue();
  });
  huntStream.addEventListener("failed", (ev) => {
    finishHunt();
    logLine("log-fail", `The hunt stopped: ${JSON.parse(ev.data).message}`);
  });
  huntStream.onerror = () => {
    if (!$("#hunt-go").disabled) return;
    finishHunt();
    logLine("log-fail", "Lost the connection to the server.");
  };
}

$("#cancel-hunt").onclick = () => {
  if (!huntStream) return;
  huntStream.close();
  huntStream = null;
  finishHunt();
  logLine("log-fail", "UPDATES STOPPED — provider requests already sent may still finish or incur cost.");
};

function finishHunt() {
  if (huntStream) { huntStream.close(); huntStream = null; }
  $("#hunt-go").disabled = !scam.api_available || scam.ephemeral_storage;
  $("#dry-run-hunt").disabled = !scam.api_available ? true : false;
  $("#hunt-go").textContent = "Run hunt";
  $("#dry-run-hunt").textContent = "Plan only";
}

function huntSummary(d) {
  const n = d.seen || 0;
  $("#hunt-stage").textContent =
    `${n} finding${n === 1 ? "" : "s"}, ${d.new || 0} new, ${d.escalated || 0} at escalate`;
  if (d.structured_disabled) {
    logLine("log-note",
      "Structured outputs were rejected — this run parsed model text instead.",
      d.structured_disabled);
  }
  const failures = d.failures || [];
  if (d.dry_run) {
    logLine("log-note", `PLAN ONLY — ${d.queries_run || 0} searches were expanded; no providers were queried and no findings were saved.`);
    return;
  }
  if (failures.length) {
    logLine("log-fail",
      `INCOMPLETE RUN — ${failures.length} of ${(d.queries_run || 0) + failures.length} queries did not search`);
    failures.slice(0, 8).forEach((f) => logLine("log-fail", f));
    if (!n) {
      logLine("log-fail", "Zero findings here does NOT mean the brand is clean.");
    }
  } else if (!d.queries_run) {
    logLine("log-fail", "No queries ran at all — check the config and API key.");
  }
}

/* ----------------------------------------------------------------- score */

$("#score-form").onsubmit = async (e) => {
  e.preventDefault();
  const out = $("#score-out");
  out.replaceChildren(el("p", "hint", "Scoring…"));
  try {
    const r = await fetch("/api/scamscan/score", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        text: $("#score-text").value, url: $("#score-url").value.trim(),
      }),
    });
    const d = await r.json();
    if (!r.ok) {
      out.replaceChildren(el("p", "errs", d.detail || "Could not score that."));
      return;
    }
    out.replaceChildren(scoreCard(d));
  } catch {
    out.replaceChildren(el("p", "errs", "Could not reach the server."));
  }
};

$("#scan-form").onsubmit = async (event) => {
  event.preventDefault();
  const button = $("#scan-go");
  const out = $("#scan-out");
  const rawUrl = $("#scan-url").value.trim();
  if (!rawUrl) {
    out.replaceChildren(el("p", "errs", "Enter a public URL to scan."));
    $("#scan-url").focus();
    return;
  }
  // Pasted domains commonly omit the scheme. Native type=url validation used
  // to reject those before this handler ran, which looked like the app had
  // lost the user's input. Accept domains and normalize them consistently.
  const scanUrl = /^[a-z][a-z\d+.-]*:\/\//i.test(rawUrl) ? rawUrl : `https://${rawUrl}`;
  let parsed;
  try { parsed = new URL(scanUrl); } catch {
    out.replaceChildren(el("p", "errs", "Enter a valid URL, for example https://example.com."));
    $("#scan-url").focus();
    return;
  }
  if (!["http:", "https:"].includes(parsed.protocol) || !parsed.hostname) {
    out.replaceChildren(el("p", "errs", "Only public http:// or https:// URLs can be scanned."));
    $("#scan-url").focus();
    return;
  }
  $("#scan-url").value = scanUrl;
  button.disabled = true;
  button.textContent = "Scanning…";
  out.replaceChildren(el("div", "scan-progress", "Safely fetching and analysing the public page…"));
  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: scanUrl }),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || "The URL could not be scanned.");
    out.replaceChildren(liveScanCard(data));
  } catch (error) {
    out.replaceChildren(el("div", "empty-inline"));
    out.firstChild.append(el("h3", null, "Scan incomplete"),
      el("p", "errs", error.message || "The server could not scan that URL."));
  } finally {
    button.disabled = false;
    button.textContent = "Fetch and scan";
  }
};

function liveScanCard(data) {
  const score = Number(data.score || 0);
  const band = score >= 80 ? "HIGH" : score >= 45 ? "MED" : score >= 20 ? "LOW" : "WEAK";
  const card = el("article", "card scan-result");
  card.style.setProperty("--band", BAND_COLOUR[band]);
  const top = el("div", "card-top");
  top.append(gauge(band), el("span", "score", Math.round(score)),
    el("span", "flag", String(data.verdict || "UNKNOWN").replaceAll("_", " ")));
  card.append(top, el("h3", null, data.classification || "Scan result"));
  if (data.confidence != null) {
    card.append(el("p", "reason", `${Math.round(data.confidence * 100)}% evidence completeness`));
  }
  const findings = el("ul", "evidence-reasons");
  (data.findings || []).forEach((finding) => findings.append(el("li", null, finding)));
  if (findings.childNodes.length) card.append(findings);
  card.append(el("p", "candidate-note",
    "Automated assessment only — verify consequential decisions against the live source and independent evidence."));
  return card;
}

function scoreCard(d) {
  const c = el("article", "card");
  c.style.setProperty("--band", BAND_COLOUR[d.band] || "var(--weak)");

  const top = el("div", "card-top");
  top.append(gauge(d.band), el("span", "score", Math.round(d.score)));
  const verdict =
    d.score >= d.escalate_threshold ? "escalate now"
    : d.score >= d.review_threshold ? "needs review"
    : "below the review threshold";
  top.append(el("span", "flag", verdict));
  c.append(top);

  c.append(familyBars(d));
  // Which families the average was taken over. The whole absent-vs-zero
  // argument is invisible unless the page says which ones reported.
  c.append(el("p", "reason",
    `averaged over: ${(d.scored_on || []).join(", ") || "nothing"}`));

  if (d.lexicon_hits?.length) c.append(hitList(d.lexicon_hits));
  else c.append(el("p", "hint", "No lexicon terms matched."));

  if (d.impersonation_reason) {
    c.append(el("p", "reason", `host: ${d.impersonation_reason}`));
  }
  const artifacts = Object.entries(d.artifacts || {});
  if (artifacts.length) {
    const tags = el("div", "tags");
    artifacts.forEach(([k, v]) => tags.append(el("span", "tag", `${k}: ${v.join(", ")}`)));
    c.append(tags);
  }
  return c;
}

init();
initScamscan();
openHashView();
