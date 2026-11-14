/* Social inbox and watchlist.

   No framework, no build step (same as the rest of the app). Every value from the API began on
   someone else's page, so every dynamic value goes through esc() and links are only ever
   http(s). A search never blocks the page: it returns a run id and this file polls it, showing
   what each source said as it answers, so an empty result always comes with its reason. */
(function () {
  const API = "/api/social";
  const $s = (sel, root = document) => root.querySelector(sel);
  const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const when = (iso) => (iso ? String(iso).replace("T", " ").slice(0, 16) + " UTC" : "never");
  const safeUrl = (u) => (/^https?:\/\//i.test(String(u || "")) ? String(u) : "#");
  const PLATFORM_LABEL = { reddit: "Reddit", tiktok: "TikTok", x: "X", facebook: "Facebook", instagram: "Instagram" };
  const STATUS_LABEL = {
    ok: "full details", partial: "some details", snippet_only: "search snippet only", no_results: "nothing found",
    not_found: "not found", blocked: "blocked", rate_limited: "rate limited", error: "error", queued: "waiting", disabled: "switched off",
  };
  const FIELD_LABEL = {
    "author.username": "handle", "author.display_name": "display name", "author.profile_url": "profile link",
    "author.followers": "followers", "author.verified": "verified status", "content.text": "text",
    "content.published_at": "date", "content.media_urls": "media", "engagement.likes": "likes",
    "engagement.comments": "comments", "engagement.shares": "shares", "engagement.views": "views",
  };
  const state = { review: "new", poll: null, run: null };

  async function api(path, options) {
    const res = await fetch(API + path, { credentials: "same-origin", headers: { "Content-Type": "application/json" }, ...options });
    let data = null;
    try { data = await res.json(); } catch (e) { /* non-JSON error body */ }
    if (!res.ok) throw new Error((data && data.detail) || `request failed (${res.status})`);
    return data;
  }
  const badge = (status) => `<span class="sx-badge sx-${esc(status)}">${esc(STATUS_LABEL[status] || status)}</span>`;
  /* A source's answer is not a hit's completeness: "ok" from a source means it returned
     results, not that those results carry full details. */
  const sourceBadge = (status) => `<span class="sx-badge sx-${esc(status)}">${esc(status === "ok" ? "results found" : (STATUS_LABEL[status] || status || "not asked"))}</span>`;
  const note = (el, msg, isError) => { el.textContent = msg; el.classList.toggle("sx-error", !!isError); el.hidden = !msg; };

  /* The analyst's name is typed once and remembered on this device only. */
  function analyst() {
    return ($s("#sx-analyst").value || $s("#sw-analyst").value || "").trim();
  }
  function rememberAnalyst(value) {
    ["#sx-analyst", "#sw-analyst"].forEach((id) => { if ($s(id).value !== value) $s(id).value = value; });
    try { localStorage.setItem("mnara.analyst", value); } catch (e) { /* storage unavailable */ }
  }
  ["#sx-analyst", "#sw-analyst"].forEach((id) => $s(id).addEventListener("input", (ev) => rememberAnalyst(ev.target.value)));
  try { rememberAnalyst(localStorage.getItem("mnara.analyst") || ""); } catch (e) { /* storage unavailable */ }

  /* ------------------------------------------------------------------ sources */
  function sourceLines(sources, worker, pending) {
    const lines = [];
    if (worker && !worker.running) lines.push(`<li class="sx-error">${esc(worker.note)}</li>`);
    if (pending) lines.push(`<li>${esc(pending)} search job${pending === 1 ? "" : "s"} waiting or running.</li>`);
    (sources || []).forEach((s) => {
      const paused = s.breaker === "open" ? ` Paused until ${esc(when(s.breaker_until))} after repeated failures.` : "";
      lines.push(`<li><strong>${esc(s.source)}</strong> ${sourceBadge(s.last_status)} ${esc(s.last_detail || "")}.${paused} `
        + `Last success ${esc(when(s.last_success_at))}.</li>`);
    });
    if (!(sources || []).length) lines.push("<li>No source has been asked yet.</li>");
    return `<ul class="sx-sources">${lines.join("")}</ul>`;
  }

  /* --------------------------------------------------------------------- hits */
  function hitCard(h) {
    const author = h.author.username ? `@${esc(h.author.username)}` : (h.author.display_name ? esc(h.author.display_name) : "author unknown");
    const text = h.content.text || h.title || "";
    const verdict = h.verdict && (h.verdict.level === "lure" || h.verdict.level === "check" || h.verdict.level === "advisory" || h.verdict.level === "official")
      ? `<p class="sx-verdict sx-verdict-${esc(h.verdict.level)}"><strong>${esc(h.verdict.label)}.</strong> ${esc(h.verdict.reason)} ${esc(h.verdict.action || "")}</p>` : "";
    const missing = (h.missing_fields || []).map((f) => FIELD_LABEL[f] || f);
    const terms = (h.matched_terms || []).map((t) => `<span class="sx-term">${esc(t)}</span>`).join("");
    const reasons = (h.reasons || []).map((r) => `<li>${esc(r.points)} · ${esc(r.basis)}</li>`).join("");
    const actions = [["relevant", "Relevant"], ["dismiss", "Dismiss"], ["escalate", "Escalate"]]
      .map(([a, label]) => `<button type="button" class="secondary-button" data-act="${a}" data-id="${esc(h.id)}">${label}</button>`).join("")
      + (h.review_status !== "new" ? `<button type="button" class="text-button" data-act="reopen" data-id="${esc(h.id)}">Move back to New</button>` : "");
    return `<article class="sx-hit" data-hit="${esc(h.id)}">
      <div class="sx-hit-top"><span class="sx-platform">${esc(PLATFORM_LABEL[h.platform] || h.platform)}</span>${badge(h.status)}
        <span class="sx-score" title="Score out of 100">${esc(h.score)}</span>
        ${h.review_status !== "new" ? `<span class="sx-review">${esc(h.review_status)}</span>` : ""}</div>
      ${h.title ? `<h3>${esc(h.title)}</h3>` : ""}
      ${verdict}
      ${text ? `<p class="sx-text">${esc(String(text).slice(0, 400))}</p>` : '<p class="sx-text sx-muted">No text was available for this result.</p>'}
      <p class="sx-meta"><span>${author}</span><span>${h.content.published_at ? esc(String(h.content.published_at).slice(0, 10)) : "date unknown"}</span>
        <span>first seen ${esc(when(h.first_seen))}</span></p>
      ${terms ? `<p class="sx-terms">Matched: ${terms}</p>` : ""}
      ${missing.length ? `<p class="sx-missing">Not available from this source: ${esc(missing.join(", "))}.</p>` : ""}
      <details class="sx-why"><summary>How the score of ${esc(h.score)} was reached</summary><ul>${reasons}</ul></details>
      <div class="sx-actions"><a class="sx-open" href="${esc(safeUrl(h.url))}" target="_blank" rel="noopener noreferrer">Open original</a>${actions}</div>
    </article>`;
  }

  async function loadHits() {
    const box = $s("#sx-hits");
    try {
      const d = await api(`/hits?review=${encodeURIComponent(state.review)}`);
      note($s("#sx-status"), d.worker.running ? "" : d.worker.note, true);
      if (d.hits.length) {
        box.innerHTML = d.hits.map(hitCard).join("");
        return;
      }
      const label = state.review === "all" ? "" : ` marked ${state.review}`;
      box.innerHTML = `<div class="sx-empty"><h3>No hits${esc(label)} yet</h3>
        <p>That does not by itself mean there is nothing to find. This is what the sources last said:</p>
        ${sourceLines(d.sources, d.worker, d.pending_jobs)}
        <p>Add terms on the <button type="button" class="text-button" data-open-social="watchlist">Watchlist</button> page, or search above.</p></div>`;
    } catch (err) {
      box.innerHTML = `<div class="sx-empty"><h3>The inbox could not be loaded</h3><p class="sx-error">${esc(err.message)}</p></div>`;
    }
  }

  $s("#sx-hits").addEventListener("click", async (ev) => {
    const open = ev.target.closest("[data-open-social]");
    if (open) { document.querySelector(`.tab[data-view="${open.dataset.openSocial}"]`)?.click(); return; }
    const btn = ev.target.closest("[data-act]");
    if (!btn) return;
    btn.disabled = true;
    try {
      await api(`/hits/${encodeURIComponent(btn.dataset.id)}/review`, { method: "POST", body: JSON.stringify({ action: btn.dataset.act, analyst: analyst() }) });
      await loadHits();
    } catch (err) {
      btn.disabled = false;
      note($s("#sx-status"), err.message, true);
    }
  });

  $s("#sx-filters").addEventListener("click", (ev) => {
    const chip = ev.target.closest("[data-review]");
    if (!chip) return;
    state.review = chip.dataset.review;
    $s("#sx-filters").querySelectorAll("[data-review]").forEach((c) => {
      c.classList.toggle("is-on", c === chip);
      c.setAttribute("aria-pressed", String(c === chip));
    });
    loadHits();
  });
  $s("#sx-refresh").addEventListener("click", loadHits);

  /* ------------------------------------------------------------------- search */
  function renderRun(run) {
    const rows = run.outcomes.map((o) => `<tr><td>${esc(PLATFORM_LABEL[o.platform] || o.platform)}</td><td>${esc(o.source)}</td>
      <td>${sourceBadge(o.status)}</td><td>${esc(o.detail || "")}</td></tr>`).join("");
    const waiting = run.state === "running";
    const headline = waiting
      ? `Searching for “${esc(run.query)}”… ${esc(run.hits.length)} found so far`
      : `Search for “${esc(run.query)}” finished: ${esc(run.hits.length)} found`;
    const nothing = !waiting && !run.hits.length
      ? '<p class="sx-muted">Nothing was found. The table shows what each source said, so you can tell “nothing there” from “could not look”.</p>' : "";
    const worker = waiting && !run.worker.running ? `<p class="sx-error">${esc(run.worker.note)}</p>` : "";
    $s("#sx-run").hidden = false;
    $s("#sx-run").innerHTML = `<h3>${headline}</h3>${worker}${nothing}
      <div class="sx-table-wrap"><table class="sx-table"><thead><tr><th>Platform</th><th>Source</th><th>Result</th><th>What it said</th></tr></thead><tbody>${rows}</tbody></table></div>
      ${run.hits.length ? `<div class="sx-run-hits">${run.hits.map(hitCard).join("")}</div>` : ""}`;
  }

  async function pollRun() {
    if (!state.run) return;
    try {
      const run = await api(`/search/${encodeURIComponent(state.run)}`);
      renderRun(run);
      if (run.state === "finished") {
        clearInterval(state.poll);
        state.poll = null;
        loadHits();
      }
    } catch (err) {
      clearInterval(state.poll);
      state.poll = null;
      note($s("#sx-status"), err.message, true);
    }
  }

  $s("#sx-search").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const button = $s("#sx-search button[type=submit]");
    button.disabled = true;
    try {
      const d = await api("/search", { method: "POST", body: JSON.stringify({
        query: $s("#sx-query").value, purpose: $s("#sx-purpose").value, analyst: analyst() }) });
      note($s("#sx-status"), "", false);
      state.run = d.run_id;
      clearInterval(state.poll);
      await pollRun();
      state.poll = setInterval(pollRun, 5000);
    } catch (err) {
      note($s("#sx-status"), err.message, true);
    } finally {
      button.disabled = false;
    }
  });
  $s("#sx-run").addEventListener("click", reviewFromRun);
  async function reviewFromRun(ev) {
    const btn = ev.target.closest("[data-act]");
    if (!btn) return;
    btn.disabled = true;
    try {
      await api(`/hits/${encodeURIComponent(btn.dataset.id)}/review`, { method: "POST", body: JSON.stringify({ action: btn.dataset.act, analyst: analyst() }) });
      await Promise.all([pollRun(), loadHits()]);
    } catch (err) {
      btn.disabled = false;
      note($s("#sx-status"), err.message, true);
    }
  }

  /* ---------------------------------------------------------------- watchlist */
  function healthTable(d) {
    if (!d.sources.length) return `<p class="sx-muted">${esc(d.note)}</p>`;
    const rows = d.sources.map((s) => `<tr><td>${esc(s.source)}</td><td>${sourceBadge(s.last_status)}</td>
      <td>${esc(when(s.last_success_at))}</td><td>${esc(when(s.last_failure_at))}</td>
      <td>${s.breaker === "open" ? `paused until ${esc(when(s.breaker_until))}` : "running"}</td>
      <td>${s.success_rate_7d == null ? "—" : esc(Math.round(s.success_rate_7d * 100)) + "% of " + esc(s.attempts_7d)}</td>
      <td>${esc(s.last_detail || "")}</td></tr>`).join("");
    return `<div class="sx-table-wrap"><table class="sx-table"><thead><tr><th>Source</th><th>Last result</th><th>Last success</th>
      <th>Last failure</th><th>State</th><th>7-day success</th><th>Detail</th></tr></thead><tbody>${rows}</tbody></table></div>`;
  }

  async function loadWatchlist() {
    try {
      const [w, h] = await Promise.all([api("/watchlist"), api("/health")]);
      const boxes = $s("#sw-platforms");
      if (!boxes.children.length) {
        boxes.innerHTML = w.platforms.map((p) => `<label class="sx-check"><input type="checkbox" value="${esc(p)}" checked> ${esc(PLATFORM_LABEL[p] || p)}</label>`).join("");
      }
      note($s("#sw-status"), h.worker.running ? "" : h.worker.note, true);
      $s("#sw-count").textContent = `${w.watchlist.length} term${w.watchlist.length === 1 ? "" : "s"}`;
      $s("#sw-list").innerHTML = w.watchlist.length ? w.watchlist.map((t) => `<article class="sx-watch${t.active ? "" : " sx-paused"}">
          <div><strong>${esc(t.term)}</strong> <span class="sx-muted">${t.match_type === "exact" ? "exact phrase" : "all the words"} · ${esc(t.platforms.map((p) => PLATFORM_LABEL[p] || p).join(", "))}${t.active ? "" : " · paused"}</span></div>
          <div class="sx-actions"><button type="button" class="secondary-button" data-toggle="${esc(t.id)}" data-active="${t.active ? "0" : "1"}">${t.active ? "Pause" : "Resume"}</button>
            <button type="button" class="text-button" data-delete="${esc(t.id)}">Remove</button></div></article>`).join("")
        : '<div class="sx-empty"><h3>The watchlist is empty</h3><p>Add a term above. Nothing is searched on a schedule until there is at least one.</p></div>';
      $s("#sw-health").innerHTML = healthTable(h);
    } catch (err) {
      note($s("#sw-status"), err.message, true);
    }
  }

  $s("#sw-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const platforms = [...$s("#sw-platforms").querySelectorAll("input:checked")].map((i) => i.value);
    try {
      await api("/watchlist", { method: "POST", body: JSON.stringify({
        term: $s("#sw-term").value, match_type: $s("#sw-match").value, platforms, analyst: analyst() }) });
      $s("#sw-term").value = "";
      note($s("#sw-status"), "", false);
      await loadWatchlist();
    } catch (err) {
      note($s("#sw-status"), err.message, true);
    }
  });

  $s("#sw-list").addEventListener("click", async (ev) => {
    const toggle = ev.target.closest("[data-toggle]");
    const remove = ev.target.closest("[data-delete]");
    try {
      if (toggle) {
        await api(`/watchlist/${encodeURIComponent(toggle.dataset.toggle)}`, { method: "PATCH", body: JSON.stringify({ active: toggle.dataset.active === "1", analyst: analyst() }) });
      } else if (remove) {
        await api(`/watchlist/${encodeURIComponent(remove.dataset.delete)}?analyst=${encodeURIComponent(analyst())}`, { method: "DELETE" });
      } else {
        return;
      }
      await loadWatchlist();
    } catch (err) {
      note($s("#sw-status"), err.message, true);
    }
  });

  $s("#sw-run").addEventListener("click", async () => {
    try {
      const d = await api("/watchlist/run", { method: "POST", body: JSON.stringify({ analyst: analyst() }) });
      note($s("#sw-status"), d.note || `${d.queued} search${d.queued === 1 ? "" : "es"} queued. Results arrive in the Social inbox.${d.worker.running ? "" : " " + d.worker.note}`, !d.queued || !d.worker.running);
    } catch (err) {
      note($s("#sw-status"), err.message, true);
    }
  });

  window.socialOnView = (view) => {
    if (view === "social") loadHits();
    if (view === "watchlist") loadWatchlist();
  };
})();
