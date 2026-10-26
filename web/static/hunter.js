/* Autonomous hunting views: feed, investigation, campaigns, operations.

   No framework, no build step (same as the rest of the app). Everything that arrives from the API
   originated on a hostile web page at some point, so every dynamic value goes through esc() and
   nothing from the API is ever placed in markup, an attribute or a URL unescaped. */
(function () {
  const API = "/api/hunter";
  const $h = (sel, root = document) => root.querySelector(sel);
  const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const short = (s, n = 14) => (String(s || "").length > n ? String(s).slice(0, n) + "…" : String(s || ""));
  const when = (iso) => (iso ? String(iso).replace("T", " ").slice(0, 16) : "—");
  const CLASS_LABEL = { HIGH_PRIORITY: "High priority", SUSPICIOUS: "Suspicious", WATCH: "Watch", LOW: "Low", UNASSESSED: "Not assessed" };
  const DISPOSITIONS = ["UNREVIEWED", "BENIGN", "FALSE_POSITIVE", "SUSPICIOUS", "CONFIRMED_IMPERSONATION", "CONFIRMED_SCAM", "MONITOR"];
  const state = { selected: null, timer: null, campaign: null };

  async function api(path, options) {
    const res = await fetch(API + path, { credentials: "same-origin", headers: { "Content-Type": "application/json" }, ...options });
    let data = null;
    try { data = await res.json(); } catch (e) { /* non-JSON error body */ }
    if (!res.ok) throw new Error((data && data.detail) || `request failed (${res.status})`);
    return data;
  }
  const chip = (cls, text, title) => `<span class="hx-chip hx-${esc(cls || "none")}"${title ? ` title="${esc(title)}"` : ""}>${esc(text)}</span>`;
  const classChip = (c) => chip(c || "UNSCORED", CLASS_LABEL[c] || (c ? c : "Not scored"));
  const note = (el, msg, isError) => { el.textContent = msg; el.classList.toggle("hx-error", !!isError); el.hidden = !msg; };

  /* ---------------------------------------------------------------- overview */
  const METRICS = [
    ["candidates_discovered", "Discovered"], ["candidates_investigated", "Investigated"], ["suspicious", "Suspicious"],
    ["high_priority", "High priority"], ["new_campaigns", "New campaigns"], ["new_domains", "New domains"],
    ["new_indicators", "New indicators"], ["pending_review", "Awaiting review"], ["false_positives", "False positives"],
  ];
  async function loadStatus() {
    const box = $h("#hx-metrics");
    try {
      const s = await api("/status");
      const TONE = { high_priority: "high", suspicious: "med", pending_review: "low" };   // colour only where it means "look here"
      box.innerHTML = METRICS.map(([k, label]) => `<div class="hx-metric${TONE[k] && s.metrics[k] > 0 ? ` hx-tone-${TONE[k]}` : ""}"><span class="hx-num">${esc(s.metrics[k])}</span><span class="hx-label">${esc(label)}</span></div>`).join("")
        + `<div class="hx-metric hx-wide"><span class="hx-num">${esc(s.providers.healthy)}<small> / ${esc(s.providers.healthy + s.providers.degraded + s.providers.failing + s.providers.not_run)}</small></span>`
        + `<span class="hx-label">Sources healthy${s.providers.failing ? ` · ${esc(s.providers.failing)} failing` : ""}${s.providers.degraded ? ` · ${esc(s.providers.degraded)} degraded` : ""}</span></div>`;
      note($h("#hx-warn"), s.persistent_storage ? "" : "This deployment's storage is temporary: dispositions and the queue will not survive a restart. Set WATCHTOWER_DATA_DIR to a persistent volume.", true);
    } catch (e) {
      box.innerHTML = "";
      note($h("#hx-warn"), `Could not load the hunter: ${e.message}`, true);
    }
  }

  /* -------------------------------------------------------------------- feed */
  function filterParams() {
    const f = $h("#hx-filters"), p = new URLSearchParams();
    for (const name of ["classification", "status", "disposition", "type", "q", "min_score"]) {
      const v = f.elements[name]?.value.trim();
      if (v) p.set(name, v);
    }
    p.set("limit", "50");
    return p.toString();
  }
  async function loadFeed() {
    const box = $h("#hx-feed");
    box.innerHTML = '<p class="hint">Loading…</p>';
    try {
      const r = await api("/candidates?" + filterParams());
      if (!r.items.length) { box.innerHTML = filterParams() === "limit=50"
        ? '<div class="hx-empty"><h3>Nothing discovered yet</h3><p>The hunter looks for lookalike domains, certificates and shared infrastructure on its own. Start it in a terminal and results appear here as each stage finishes.</p><pre>python run.py hunt          # keep running\npython run.py hunt --once   # one pass</pre></div>'
        : '<div class="hx-empty"><h3>No candidates match these filters</h3><p>Loosen a filter, or clear the search box.</p></div>'; return; }
      box.innerHTML = `<p class="hint" aria-live="polite">${esc(r.total)} match${r.total === 1 ? "" : "es"}${r.total > r.items.length ? `, showing ${esc(r.items.length)}` : ""}</p>`
        + `<div class="hx-table-wrap"><table class="hx-table"><thead><tr><th>Last seen</th><th>Indicator</th><th>Type</th><th>Market</th><th>Source</th><th>Risk</th><th>Class</th><th>Campaign</th><th>Status</th><th>Review</th></tr></thead><tbody>`
        + r.items.map((i) => `<tr><td>${esc(when(i.last_seen))}</td>`
          + `<td><button type="button" class="hx-link" data-open="${esc(i.id)}">${esc(short(i.indicator, 46))}</button></td>`
          + `<td>${esc(i.type)}</td><td>${esc(i.market || "—")}</td><td>${esc(i.source)}</td>`
          + `<td class="hx-risk">${i.risk_score == null ? "—" : `<span class="hx-bar" aria-hidden="true"><i style="width:${Math.max(0, Math.min(100, Math.round(i.risk_score)))}%"></i></span><b>${esc(Math.round(i.risk_score))}</b>`}</td><td>${classChip(i.classification)}</td>`
          + `<td>${esc(i.campaign || "—")}</td><td>${esc(i.status)}${i.deferred_reason ? ` ${chip("none", "deferred", i.deferred_reason)}` : ""}</td>`
          + `<td>${esc(i.disposition || "Unreviewed")}</td></tr>`).join("") + "</tbody></table></div>";
      box.querySelectorAll("[data-open]").forEach((b) => b.addEventListener("click", () => openInvestigation(b.dataset.open)));
    } catch (e) { box.innerHTML = `<p class="hint hx-error">${esc(e.message)}</p>`; }
  }

  /* ----------------------------------------------------------- investigation */
  function reasonRow(r) {
    const sign = r.weight > 0 ? "+" : "";
    const ids = r.evidence_ids && r.evidence_ids.length ? ` <span class="hx-ids" title="${esc(r.evidence_ids.join("\n"))}">evidence ${esc(r.evidence_ids.map((x) => short(x.split(":").pop(), 8)).join(", "))}</span>` : ` <span class="hx-ids">${esc(r.basis)}</span>`;
    return `<li class="${r.weight < 0 ? "hx-neg" : ""}"><b class="hx-weight">${esc(sign + r.weight)}</b> <span>${esc(r.signal.replace(/_/g, " "))}</span> — ${esc(r.evidence)}${ids}</li>`;
  }
  function chainHtml(chain) {
    return `<ol class="hx-chain">` + chain.map((c, i) => {
      const via = c.via && c.via.pivot_from ? ` · via ${esc(c.via.where || "link")} on ${esc(c.via.pivot_from)}` : "";
      return `<li><b>${esc(c.type)}</b> ${esc(short(c.canonical, 60))}<br><span class="hint">${i ? "found by" : "discovered by"} ${esc(c.source)}${c.query ? ` (${esc(short(c.query, 70))})` : ""}${via} · ${esc(when(c.first_seen))}</span></li>`;
    }).join("") + "</ol>";
  }
  function indicatorsHtml(groups) {
    const names = Object.keys(groups);
    if (!names.length) return '<p class="hint">No indicators extracted yet.</p>';
    return names.map((g) => `<div class="hx-group"><h4>${esc(g)}</h4><div class="chips">` + groups[g].map((i) => `<button type="button" class="chip hx-ind" data-ind="${esc(i.id)}" title="${esc(i.relationship)} · confidence ${esc(i.confidence)}">${esc(short(i.value, 40))}</button>`).join("") + "</div></div>").join("");
  }
  function evidenceHtml(items) {
    if (!items.length) return '<p class="hint">No evidence stored.</p>';
    return items.slice().reverse().map((e) => `<details class="hx-ev"><summary><b>${esc(e.evidence_type)}</b> · ${esc(e.source)} · ${esc(when(e.observed_at))}${e.raw_metadata.personal_data ? " " + chip("none", "personal data") : ""}${e.raw_metadata.purged ? " " + chip("none", "purged") : ""}</summary>`
      + `<p class="hint">id ${esc(e.id)} · confidence ${esc(e.confidence)}${e.source_url ? ` · from ${esc(e.source_url)}` : ""}</p><pre>${esc(short(e.observed_value, 1200))}</pre></details>`).join("");
  }
  async function openInvestigation(id) {
    const box = $h("#hx-detail");
    state.selected = id;
    box.hidden = false;
    box.innerHTML = '<p class="hint">Loading investigation…</p>';
    box.scrollIntoView({ behavior: "smooth", block: "start" });
    history.replaceState(null, "", "#hunt/" + encodeURIComponent(id));
    try {
      const r = await api("/investigations/" + encodeURIComponent(id));
      const c = r.candidate, sc = r.score;
      const unassessed = sc && sc.coverage && sc.coverage.unassessed && sc.coverage.unassessed.length ? sc.coverage.unassessed : [];
      box.innerHTML = `<header class="hx-detail-head"><div><span class="eyebrow">${esc(c.type)} · ${esc(c.source)}${c.market ? " · " + esc(c.market) : ""}</span>`
        + `<h2 tabindex="-1" id="hx-detail-title">${esc(c.indicator)}</h2></div><div class="hx-score"><span class="hx-num">${c.risk_score == null ? "—" : esc(Math.round(c.risk_score))}<small> / 100</small></span>${classChip(c.classification)}</div>`
        + `<button type="button" class="secondary-button" id="hx-close">Close</button></header>`
        + `<p class="hint">Status ${esc(c.status)}${c.stage && c.stage !== "none" ? " (" + esc(c.stage) + " pass)" : ""} · first seen ${esc(when(c.first_seen))} · last investigated ${esc(when(c.last_investigated))} · seen ${esc(c.sightings)}× by ${esc(c.sources_seen.join(", "))}`
        + `${r.campaign ? ` · <button type="button" class="hx-link" data-campaign="${esc(r.campaign.id)}">${esc(r.campaign.name)}</button>` : ""}</p>`
        + (unassessed.length ? `<p class="hint hx-error">Not fully assessed: ${esc(unassessed.join("; "))}. A low score here means "not seen", not "clean".</p>` : "")
        + `<section><h3>Why Mnara flagged it</h3>${r.why_flagged.length ? `<ul class="hx-reasons">${r.why_flagged.map(reasonRow).join("")}</ul>` : '<p class="hint">No scoring factors fired.</p>'}`
        + `${sc ? `<p class="hint">Scored under configuration ${esc(sc.config_hash)} · assessment ${esc(sc.assessment)}</p>` : ""}</section>`
        + `<section><h3>How Mnara found it</h3>${chainHtml(r.how_found)}</section>`
        + `<section><h3>Indicators</h3>${indicatorsHtml(r.indicators)}<div id="hx-indicator-detail"></div></section>`
        + `<section><h3>Relationships</h3>${r.relationships.length ? `<div class="hx-table-wrap"><table class="hx-table"><thead><tr><th>Relationship</th><th>Target</th><th>Confidence</th><th>Evidence</th></tr></thead><tbody>${r.relationships.slice(0, 60).map((x) => `<tr><td>${esc(x.relationship_type.replace(/_/g, " "))}</td><td>${esc(short(x.other_value, 60))}</td><td>${esc(x.confidence)}</td><td class="hx-ids">${esc(short((x.evidence_id || "").split(":").pop(), 10))}</td></tr>`).join("")}</tbody></table></div>` : '<p class="hint">None yet.</p>'}</section>`
        + `<section><h3>Score history</h3><ul class="hx-history">${r.score_history.map((h) => `<li>${esc(when(h.scored_at))} · <b>${esc(h.score)}</b> ${esc(CLASS_LABEL[h.classification] || h.classification)}${h.delta == null ? "" : ` (${esc(h.delta > 0 ? "+" : "")}${esc(h.delta)})`} · ${esc(h.trigger)}${h.changes.length ? ` · ${esc(h.changes.slice(0, 4).map((x) => x.change + " " + x.signal).join(", "))}` : ""}</li>`).join("") || "<li>Not scored yet.</li>"}</ul>`
        + `${r.changes.length ? `<h4>Changes noticed</h4><ul class="hx-history">${r.changes.map((x) => `<li>${esc(when(x.at))} · ${x.meaningful ? "<b>meaningful</b> " : ""}${esc(x.summary)}</li>`).join("")}</ul>` : ""}</section>`
        + `<section><h3>Evidence</h3>${evidenceHtml(r.evidence)}</section>`
        + `<section><h3>Analyst decision</h3>${dispositionForm("candidate", c.id, r.dispositions)}</section>`;
      $h("#hx-close", box).onclick = () => { box.hidden = true; };
      box.querySelectorAll("[data-campaign]").forEach((b) => b.addEventListener("click", () => { document.querySelector('.tab[data-view="campaigns"]')?.click(); openCampaign(b.dataset.campaign); }));
      box.querySelectorAll("[data-ind]").forEach((b) => b.addEventListener("click", () => showIndicator(b.dataset.ind)));
      wireDisposition(box, "candidate", c.id, () => { openInvestigation(id); loadFeed(); loadStatus(); });
      $h("#hx-detail-title").focus();
    } catch (e) { box.innerHTML = `<p class="hint hx-error">${esc(e.message)}</p>`; }
  }
  async function showIndicator(id) {
    const box = $h("#hx-indicator-detail");
    try {
      const r = await api("/indicators/" + encodeURIComponent(id));
      box.innerHTML = `<div class="hx-sub"><b>${esc(r.entity.entity_type)}</b> ${esc(r.entity.canonical_value)}<br>`
        + (r.used_by.length ? `Used by ${r.used_by.map((u) => `${esc(u.domain)} ${classChip(u.classification)}`).join(", ")}` : "Not used by any other investigated domain.")
        + (r.campaigns.length ? `<br>Campaigns: ${esc(r.campaigns.map((c) => c.public_id).join(", "))}` : "") + "</div>";
    } catch (e) { box.innerHTML = `<p class="hint hx-error">${esc(e.message)}</p>`; }
  }

  function dispositionForm(kind, id, history) {
    const past = history.length ? `<ul class="hx-history">${history.slice().reverse().map((d) => `<li>${esc(when(d.at))} · <b>${esc(d.disposition)}</b> by ${esc(d.analyst)} (${esc(d.identity_source.replace("_", "-"))}) — ${esc(d.reason)}${d.notes ? ` · ${esc(d.notes)}` : ""}</li>`).join("")}</ul>` : '<p class="hint">No decision recorded yet.</p>';
    return `${past}<form class="hx-form" data-kind="${esc(kind)}" autocomplete="off"><label>Decision<select name="disposition">${DISPOSITIONS.map((d) => `<option value="${esc(d)}">${esc(d.replace(/_/g, " ").toLowerCase())}</option>`).join("")}</select></label>`
      + `<label>Reason (required)<textarea name="reason" rows="2" maxlength="2000" required></textarea></label><label>Notes<textarea name="notes" rows="2" maxlength="4000"></textarea></label>`
      + `<label>Your name<input name="analyst" maxlength="100" autocomplete="name"></label><p class="hint">Recorded as the signed-in account when sign-in is on; otherwise as the name you type, marked as unverified. Decisions are never deleted, and confirming one rescoring related domains.</p>`
      + `<button type="submit">Record decision</button><span class="hint hx-result" role="status"></span></form>`;
  }
  function wireDisposition(root, kind, id, done) {
    const form = $h(".hx-form", root);
    if (!form) return;
    form.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      const out = $h(".hx-result", form), data = Object.fromEntries(new FormData(form).entries());
      out.textContent = "Saving…";
      try {
        const r = await api(`/${kind === "campaign" ? "campaigns" : "candidates"}/${encodeURIComponent(id)}/disposition`, { method: "POST", body: JSON.stringify(data) });
        out.textContent = `Recorded${r.rescored ? `; ${r.rescored} related domain${r.rescored === 1 ? "" : "s"} rescored` : ""}.`;
        done();
      } catch (e) { out.textContent = e.message; out.classList.add("hx-error"); }
    });
  }

  /* --------------------------------------------------------------- campaigns */
  async function loadCampaigns() {
    const box = $h("#hx-campaigns");
    try {
      const r = await api("/campaigns");
      if (!r.items.length) { box.innerHTML = '<p class="hint">No campaigns yet. A campaign forms when two investigated domains share a strong link (a phone number, payment id, Telegram handle, wallet, analytics id or credential endpoint) or two independent medium links.</p>'; return; }
      box.innerHTML = r.items.map((c) => `<article class="hx-card"><header><button type="button" class="hx-link" data-campaign="${esc(c.id)}"><b>${esc(c.name)}</b></button> ${classChip(c.system_classification)}</header>`
        + `<p class="hint">${esc(c.public_id)} · confidence ${esc(c.correlation_score)} (${esc(c.correlation_label)}) · first seen ${esc(when(c.first_seen))} · last active ${esc(when(c.last_active))}</p>`
        + `<p>${Object.entries(c.infrastructure).map(([k, v]) => `${esc(v)} ${esc(k.toLowerCase())}`).join(" · ")}</p></article>`).join("");
      box.querySelectorAll("[data-campaign]").forEach((b) => b.addEventListener("click", () => openCampaign(b.dataset.campaign)));
    } catch (e) { box.innerHTML = `<p class="hint hx-error">${esc(e.message)}</p>`; }
  }
  function graphSvg(g) {
    const members = g.nodes.filter((n) => n.member), others = g.nodes.filter((n) => !n.member).slice(0, 40);
    const W = 640, H = 360, cx = W / 2, cy = H / 2, pos = {};
    members.forEach((n, i) => { const a = (i / Math.max(members.length, 1)) * 2 * Math.PI; pos[n.id] = [cx + Math.cos(a) * 90, cy + Math.sin(a) * 90]; });
    others.forEach((n, i) => { const a = (i / Math.max(others.length, 1)) * 2 * Math.PI + 0.3; pos[n.id] = [cx + Math.cos(a) * 150, cy + Math.sin(a) * 150]; });
    const edges = g.edges.filter((e) => pos[e.source] && pos[e.target]).map((e) => `<line x1="${pos[e.source][0].toFixed(0)}" y1="${pos[e.source][1].toFixed(0)}" x2="${pos[e.target][0].toFixed(0)}" y2="${pos[e.target][1].toFixed(0)}"><title>${esc(e.type)} · confidence ${esc(e.confidence)}</title></line>`).join("");
    const nodes = [...members, ...others].map((n) => `<g class="hx-node ${n.member ? "hx-member" : ""}" transform="translate(${pos[n.id][0].toFixed(0)},${pos[n.id][1].toFixed(0)})"><circle r="${n.member ? 8 : 5}"/><text y="${n.member ? -12 : -8}" text-anchor="middle">${esc(short(n.label, 22))}</text><title>${esc(n.type)}: ${esc(n.label)}</title></g>`).join("");
    return `<svg class="hx-graph" viewBox="0 0 ${W} ${H}" role="img" aria-label="Campaign graph: ${members.length} domains and ${others.length} shared indicators">${edges}${nodes}</svg>`;
  }
  async function openCampaign(id) {
    const box = $h("#hx-campaign-detail");
    box.hidden = false;
    box.innerHTML = '<p class="hint">Loading…</p>';
    try {
      const [c, g] = await Promise.all([api("/campaigns/" + encodeURIComponent(id)), api(`/campaigns/${encodeURIComponent(id)}/graph`)]);
      box.innerHTML = `<header class="hx-detail-head"><div><span class="eyebrow">${esc(c.public_id)}</span><h2 tabindex="-1" id="hx-campaign-title">${esc(c.name)}</h2></div><div class="hx-score">${classChip(c.system_classification)}<span class="hint">confidence ${esc(c.correlation_score)}</span></div></header>`
        + `<p>${Object.entries(c.infrastructure).map(([k, v]) => `${esc(v)} ${esc(k.toLowerCase())}`).join(" · ")}</p>`
        + `<section><h3>Graph</h3>${graphSvg(g)}</section>`
        + `<section><h3>Why Mnara believes they are related</h3>${c.why_related.length ? `<ul class="hx-reasons">${c.why_related.map((w) => `<li><b>${esc(w.link.replace(/_/g, " "))}</b> (${esc(w.strength)}) — ${esc((w.nodes || []).join(", "))} between ${esc((w.between || []).join(" and "))} <span class="hx-ids">${esc((w.based_on || []).length)} sightings</span></li>`).join("")}</ul>` : '<p class="hint">No link detail.</p>'}</section>`
        + `<section><h3>Members</h3><div class="hx-table-wrap"><table class="hx-table"><thead><tr><th>Domain</th><th>Risk</th><th>Class</th><th>Status</th></tr></thead><tbody>${c.members.map((m) => `<tr><td><button type="button" class="hx-link" data-open="${esc(m.id)}">${esc(m.domain)}</button></td><td class="hx-num-cell">${m.risk_score == null ? "—" : esc(Math.round(m.risk_score))}</td><td>${classChip(m.classification)}</td><td>${esc(m.status || "—")}</td></tr>`).join("")}</tbody></table></div></section>`
        + `<section><h3>History</h3><ul class="hx-history">${c.events.map((e) => `<li>${esc(when(e.at))} · ${esc(e.event)}${e.detail.added && e.detail.added.length ? " · added " + esc(e.detail.added.join(", ")) : ""}${e.detail.merged_from && e.detail.merged_from.length ? " · merged " + esc(e.detail.merged_from.join(", ")) : ""}</li>`).join("")}</ul></section>`
        + `<section><h3>Analyst decision</h3>${dispositionForm("campaign", c.id, c.dispositions)}</section>`;
      box.querySelectorAll("[data-open]").forEach((b) => b.addEventListener("click", () => { document.querySelector('.tab[data-view="hunt"]')?.click(); openInvestigation(b.dataset.open); }));
      wireDisposition(box, "campaign", c.id, () => { openCampaign(id); loadCampaigns(); });
      $h("#hx-campaign-title").focus();
    } catch (e) { box.innerHTML = `<p class="hint hx-error">${esc(e.message)}</p>`; }
  }

  /* -------------------------------------------------------------- operations */
  async function loadOps() {
    const qbox = $h("#hx-queue"), sbox = $h("#hx-sources"), abox = $h("#hx-alerts"), ibox = $h("#hx-insights");
    try {
      const q = await api("/queue");
      qbox.innerHTML = `<div class="hx-metrics">${[["queued", "Queued"], ["running", "Running"], ["completed", "Completed"], ["failed", "Failed"], ["retrying", "Retrying"], ["deferred", "Deferred"], ["stored_only", "Stored only"]].map(([k, l]) => `<div class="hx-metric"><span class="hx-num">${esc(q[k])}</span><span class="hx-label">${esc(l)}</span></div>`).join("")}</div>`
        + (q.deferred_reasons.length ? `<h4>Why work is deferred</h4><ul class="hx-history">${q.deferred_reasons.map((d) => `<li><b>${esc(d.n)}</b> · ${esc(d.reason)} · next ${esc(when(d.next))}</li>`).join("")}</ul>` : "")
        + (q.recent_failures.length ? `<h4>Recent failures</h4><ul class="hx-history">${q.recent_failures.map((f) => `<li>${esc(f.canonical)} · ${esc(f.error_state)} · attempt ${esc(f.attempts)}</li>`).join("")}</ul>` : "");
    } catch (e) { qbox.innerHTML = `<p class="hint hx-error">${esc(e.message)}</p>`; }
    try {
      const p = await api("/providers");
      sbox.innerHTML = `<div class="hx-table-wrap"><table class="hx-table"><thead><tr><th>Source</th><th>Status</th><th>Last success</th><th>Results</th><th>Latency</th><th>Availability</th><th>Note</th></tr></thead><tbody>${p.sources.map((s) => `<tr><td>${esc(s.source)}</td><td>${chip(s.status, s.status.replace("_", " "))}</td><td>${esc(when(s.last_success))}</td><td>${s.last_result_count == null ? "—" : esc(s.last_result_count)}</td><td>${s.avg_latency_ms == null ? "—" : esc(s.avg_latency_ms) + " ms"}</td><td>${s.availability == null ? "—" : esc(Math.round(s.availability * 100)) + "%"}</td><td>${esc(short(s.reason || s.last_error || (s.circuit_until ? "paused until " + when(s.circuit_until) : ""), 90))}</td></tr>`).join("")}</tbody></table></div>`
        + (p.jobs.length ? `<p class="hint">Scheduler last ran: ${p.jobs.map((j) => `${esc(j.job)} ${esc(when(j.last_run))}`).join(" · ")}</p>` : '<p class="hint">The scheduler has not run yet.</p>');
    } catch (e) { sbox.innerHTML = `<p class="hint hx-error">${esc(e.message)}</p>`; }
    try {
      const a = await api("/alerts?limit=30");
      abox.innerHTML = a.items.length ? `<ul class="hx-alerts">${a.items.map((x) => `<li class="${x.acknowledged_at ? "hx-acked" : ""}">${chip(x.severity === "high" ? "HIGH_PRIORITY" : "WATCH", x.severity)} <b>${esc(x.title)}</b> <span class="hint">${esc(when(x.at))} · ${esc(x.kind.replace(/_/g, " "))}${x.acknowledged_at ? ` · acknowledged by ${esc(x.acknowledged_by)}` : ""}</span>${x.acknowledged_at ? "" : ` <button type="button" class="secondary-button" data-ack="${esc(x.id)}">Acknowledge</button>`}</li>`).join("")}</ul>` : '<p class="hint">No alerts. Alerts are rare by design: a new high-priority finding, a campaign that grows, known infrastructure reappearing, a large risk rise, or a source failing repeatedly.</p>';
      abox.querySelectorAll("[data-ack]").forEach((b) => b.addEventListener("click", async () => {
        const who = window.prompt("Your name, for the record:");
        if (!who) return;
        try { await api(`/alerts/${encodeURIComponent(b.dataset.ack)}/ack`, { method: "POST", body: JSON.stringify({ analyst: who }) }); loadOps(); loadStatus(); } catch (e) { window.alert(e.message); }
      }));
    } catch (e) { abox.innerHTML = `<p class="hint hx-error">${esc(e.message)}</p>`; }
    try {
      const i = await api("/insights");
      ibox.innerHTML = `<p class="hint">Learned from ${esc(i.confirmed)} confirmed and ${esc(i.cleared)} cleared cases (at least ${esc(i.min_support)} needed). These are shown for an administrator; nothing here changes a scoring weight.</p>`
        + (i.patterns.length ? `<h4>Combinations seen in confirmed cases</h4><ul class="hx-history">${i.patterns.map((p) => `<li>${esc(p.signals.join(" + ").replace(/_/g, " "))} — ${esc(p.confirmed_cases)} confirmed, ${esc(p.false_positive_cases)} false positive</li>`).join("")}</ul>` : "")
        + (i.suggestions.length ? `<h4>Suggested trusted classifications (need approval)</h4><ul class="hx-history">${i.suggestions.map((s) => `<li>${esc(s.type.replace("_", " "))} <b>${esc(s.value)}</b> — ${esc(s.cases)} false positives (${esc(s.examples.join(", "))})${s.type === "trusted_domain" ? ` <button type="button" class="secondary-button" data-trust="${esc(s.value)}">Approve</button>` : ""}</li>`).join("")}</ul>` : "")
        + (i.approved_trusted.length ? `<h4>Approved</h4><ul class="hx-history">${i.approved_trusted.map((t) => `<li>${esc(t.value)} · ${esc(t.by)} (${esc(t.identity_source.replace("_", "-"))}) · ${esc(t.reason)}</li>`).join("")}</ul>` : "");
      ibox.querySelectorAll("[data-trust]").forEach((b) => b.addEventListener("click", async () => {
        const who = window.prompt("Your name, for the record:"), reason = who && window.prompt(`Why is ${b.dataset.trust} trusted?`);
        if (!who || !reason) return;
        try { await api("/trusted-domains", { method: "POST", body: JSON.stringify({ domain: b.dataset.trust, analyst: who, reason }) }); loadOps(); } catch (e) { window.alert(e.message); }
      }));
    } catch (e) { ibox.innerHTML = `<p class="hint hx-error">${esc(e.message)}</p>`; }
  }

  /* ------------------------------------------------------------------- wiring */
  function onView(view) {
    clearInterval(state.timer);
    if (view === "hunt") { loadStatus(); loadFeed(); state.timer = setInterval(() => { if (!document.hidden) loadStatus(); }, 60000); }
    else if (view === "campaigns") loadCampaigns();
    else if (view === "huntops") loadOps();
  }
  window.hunterOnView = onView;

  /* Deep links: #hunt/<candidate id> and #campaigns/<campaign id> open that record, so a finding can be shared. */
  function routeFromHash() {
    const m = decodeURIComponent(location.hash).match(/^#(hunt|campaigns)\/([A-Za-z0-9:_.\-]{1,120})$/);
    if (!m) return false;
    const view = m[1], id = m[2];
    const tab = document.querySelector(`.tab[data-view="${view}"]`);
    if (tab && !tab.classList.contains("is-on")) tab.click();      // the tab handler rewrites the hash to #view
    history.replaceState(null, "", `#${view}/${id}`);
    if (view === "hunt") openInvestigation(id); else openCampaign(id);
    return true;
  }
  window.addEventListener("hashchange", routeFromHash);
  const filters = $h("#hx-filters");
  if (filters) {
    filters.addEventListener("submit", (e) => { e.preventDefault(); loadFeed(); });
    filters.addEventListener("change", loadFeed);
    $h("#hx-refresh")?.addEventListener("click", () => { loadStatus(); loadFeed(); });
  }
  // app.js may already have activated one of our tabs from the URL (a bookmarked #huntops) before this
  // script registered its loader, so load whichever of our views is showing now.
  if (!routeFromHash()) {
    const showing = document.querySelector(".tab.is-on")?.dataset.view;
    if (["hunt", "campaigns", "huntops"].includes(showing)) onView(showing);
  }
})();
