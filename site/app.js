/* AP2 Conformance microsite — vanilla, no deps. Data is baked in data.js. */
(function () {
  "use strict";
  const DATA = window.__AP2_CONFORMANCE__ || { results: [], core: { passed: 0, total: 0 }, hardening: { passed: 0, total: 0 }, conformant: false };
  const $ = (s, r = document) => r.querySelector(s);
  const el = (t, c, h) => { const e = document.createElement(t); if (c) e.className = c; if (h != null) e.innerHTML = h; return e; };

  /* ---------- hero + provenance ---------- */
  $("#heroCount").textContent = String(DATA.results.length || 67);
  if (DATA.ap2Commit) $("#provCommit").textContent = DATA.ap2Commit.slice(0, 7);

  /* ---------- matrix ---------- */
  const CATEGORY_ORDER = ["chain", "payment-constraints", "checkout-constraints", "checkout-chain", "receipt-reference", "hash-pairs"];
  const byCat = new Map();
  for (const r of DATA.results) {
    if (!byCat.has(r.category)) byCat.set(r.category, []);
    byCat.get(r.category).push(r);
  }
  const cats = [...byCat.keys()].sort((a, b) => {
    const ia = CATEGORY_ORDER.indexOf(a), ib = CATEGORY_ORDER.indexOf(b);
    return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib);
  });

  const matrix = $("#matrix");
  const fills = [];
  for (const cat of cats) {
    const rows = byCat.get(cat);
    const core = rows.filter((r) => r.profile === "core");
    const hard = rows.filter((r) => r.profile === "hardening");
    const corePass = core.filter((r) => r.passed).length;
    const hardPass = hard.filter((r) => r.passed).length;
    const pct = core.length ? Math.round((corePass / core.length) * 100) : 100;

    const card = el("div", "cat");
    const head = el("div", "cat-head");
    head.appendChild(el("span", "cat-name", cat));
    const bar = el("div", "cat-bar");
    const fill = el("div", "cat-fill");
    bar.appendChild(fill); head.appendChild(bar);
    fills.push({ fill, pct });
    head.appendChild(el("span", "cat-count", `${corePass}/${core.length} core`));
    head.appendChild(el("span", "cat-hard", hard.length ? `${hardPass}/${hard.length} harden` : ""));
    head.appendChild(el("span", "cat-caret", "▸"));
    card.appendChild(head);

    const body = el("div", "cat-body");
    const grid = el("div", "cat-vectors");
    for (const r of rows) {
      const row = el("div", "vec-row");
      row.appendChild(el("span", "vmark" + (r.passed ? "" : " fail"), r.passed ? "✓" : "✗"));
      row.appendChild(el("span", "vname", r.name));
      row.appendChild(el("span", "vec-tag " + r.profile, r.profile));
      grid.appendChild(row);
    }
    body.appendChild(grid);
    card.appendChild(body);
    head.addEventListener("click", () => card.classList.toggle("open"));
    matrix.appendChild(card);
  }

  /* big stats */
  $("#coreTotal").textContent = DATA.core.total;
  $("#hardTotal").textContent = DATA.hardening.total;
  const verdict = $("#verdict");
  if (DATA.conformant) { verdict.textContent = "✅ CONFORMANT"; verdict.classList.add("pass"); }
  else { verdict.textContent = "❌ core failures"; }

  function countUp(node, to, ms) {
    const start = performance.now();
    function step(now) {
      const p = Math.min(1, (now - start) / ms);
      node.textContent = String(Math.round((1 - Math.pow(1 - p, 3)) * to));
      if (p < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  }

  /* animate stats + bars once the matrix scrolls into view */
  let matrixAnimated = false;
  const matrixIO = new IntersectionObserver((entries) => {
    entries.forEach((e) => {
      if (e.isIntersecting && !matrixAnimated) {
        matrixAnimated = true;
        countUp($("#coreNum"), DATA.core.passed, 1100);
        countUp($("#hardNum"), DATA.hardening.passed, 1100);
        fills.forEach(({ fill, pct }, i) => setTimeout(() => (fill.style.width = pct + "%"), 120 + i * 90));
      }
    });
  }, { threshold: 0.3 });
  matrixIO.observe($(".matrix-head"));

  /* ---------- anatomy guards ---------- */
  const GUARDS = [
    { id: "trust", label: "root trust · kid / x5c", title: "The root is signed by a key you trust",
      plain: "The first slip must be signed by a key the verifier already trusts — looked up by kid in a local list, or proven by an x5c certificate chain up to a trusted root. No trust anchor means no valid chain.",
      vectors: ["valid_x5c", "wrong_root_key", "x5c_untrusted_root", "kid-lookup"] },
    { id: "sig", label: "signatures · ES256", title: "Every signature is ES256 — no downgrades",
      plain: "Every slip is signed with ES256 (ECDSA on P-256). 'none', HS256 and friends are rejected before any signature math, closing the classic algorithm-confusion downgrade.",
      vectors: ["alg_swap_none_root", "alg_swap_hs256_hop", "tampered_root_payload"] },
    { id: "cnf", label: "cnf delegation", title: "Authority flows down by key, not by name",
      plain: "Each slip carries a cnf claim naming the public key allowed to sign the next hop. Intermediate hops must carry it; the terminal hop must not. Trust is passed by key.",
      vectors: ["wrong_cnf_key", "intermediate_without_cnf", "terminal_with_cnf"] },
    { id: "binding", label: "binding · sd_hash", title: "Hops can't be spliced between chains",
      plain: "Each hop is cryptographically bound to the exact previous slip via exactly one of sd_hash / issuer_jwt_hash. Both-present or neither-present is an error, so a hop can't be lifted from another chain.",
      vectors: ["binding_sd_hash_mismatch", "both_binding_claims", "neither_binding_claim"] },
    { id: "audience", label: "aud + nonce", title: "Bound to THIS merchant, once",
      plain: "The terminal slip must be bound to this merchant's audience and a one-time nonce. A slip minted for shop A can't be replayed at shop B — and a chain truncated to drop its terminal hop is rejected.",
      vectors: ["aud_mismatch", "nonce_mismatch", "truncation-reject"] },
    { id: "constraints", label: "constraints", title: "The spend obeys the authorized limits",
      plain: "The concrete purchase must satisfy the open mandate's limits — budget, amount range, allowed payees/instruments, recurrence, execution window. Unknown constraints fail closed, they're never skipped.",
      vectors: ["payment-constraints ×24", "checkout-constraints ×11"] },
    { id: "receipt", label: "receipt reference", title: "A tamper-proof link for receipts",
      plain: "The Mandate Receipt reference is the hash of the final slip, recomputed from bytes — so receipts and disputes point at exactly what was verified, never a trusted claim.",
      vectors: ["receipt-reference ×4"] },
  ];
  const guardsEl = $("#guards");
  const detailEl = $("#guardDetail");
  GUARDS.forEach((g, i) => {
    const chip = el("button", "guard-chip", g.label);
    chip.addEventListener("click", () => {
      guardsEl.querySelectorAll(".guard-chip").forEach((c) => c.classList.remove("active"));
      chip.classList.add("active");
      detailEl.innerHTML = "";
      detailEl.appendChild(el("div", "gd-title", g.title));
      detailEl.appendChild(el("div", "gd-plain", g.plain));
      const vs = el("div", "gd-vectors");
      vs.appendChild(el("span", "gd-label", ""));
      g.vectors.forEach((v) => vs.appendChild(el("span", "gd-vec", v)));
      detailEl.appendChild(vs);
    });
    guardsEl.appendChild(chip);
    if (i === 0) chip.click();
  });

  /* ---------- forgery walkthrough ---------- */
  const STEPS = [
    { ok: true, text: "root signature — ES256 under the trusted issuer key", note: "ok" },
    { ok: true, text: "cnf chain — user → agent → terminal", note: "each hop signed by the named key" },
    { ok: true, text: "binding — sd_hash matches the prior slip", note: "not spliced" },
    { ok: true, text: "terminal nonce — matches the merchant challenge", note: "ok" },
    { ok: false, text: "terminal aud = 'shop-A'  ≠  expected 'shop-B'", note: "replay across merchants — REJECTED" },
  ];
  const tsBody = $("#tsBody");
  const replayBtn = $("#replayBtn");
  let timers = [];
  function runSim() {
    timers.forEach(clearTimeout); timers = [];
    tsBody.innerHTML = "";
    replayBtn.disabled = true;
    STEPS.forEach((s, i) => {
      const line = el("div", "ts-line " + (s.ok ? "ok" : "fail"));
      line.appendChild(el("span", "mark", s.ok ? "✓" : "✗"));
      const txt = el("span", "txt", s.text + (s.note ? `  <span class="note">— ${s.note}</span>` : ""));
      line.appendChild(txt);
      tsBody.appendChild(line);
      timers.push(setTimeout(() => line.classList.add("show"), 350 + i * 650));
    });
    timers.push(setTimeout(() => (replayBtn.disabled = false), 350 + STEPS.length * 650));
  }
  replayBtn.addEventListener("click", runSim);
  // auto-run once when scrolled into view
  let simRan = false;
  new IntersectionObserver((entries) => {
    entries.forEach((e) => { if (e.isIntersecting && !simRan) { simRan = true; runSim(); } });
  }, { threshold: 0.4 }).observe($("#walkthrough"));

  /* ---------- glossary ---------- */
  const TERMS = [
    ["SD-JWT", "Selective-Disclosure JWT — a token where some claims are hidden behind salted hashes and revealed selectively."],
    ["KB-SD-JWT", "Key-Binding SD-JWT — an SD-JWT plus a proof the holder controls a key (cnf) and is bound to a context (aud, nonce). One delegation hop."],
    ["dSD-JWT", "The delegated chain: a root SD-JWT plus KB-SD-JWT hops, chained to pass authority down a path."],
    ["cnf", "Confirmation claim (RFC 7800) — names the public key allowed to sign the next hop. The delegation link."],
    ["kid", "Key id — look the verifying key up in a local trusted-key list. One way to trust the root."],
    ["x5c", "An X.509 cert chain carried in the header; trust = it chains up to a configured root CA. The other way to trust the root."],
    ["aud", "Audience — who the terminal slip is for. Forced to the merchant's identity so it can't be replayed elsewhere."],
    ["nonce", "A one-time challenge the merchant issues; binds the presentation to this request."],
    ["sd_hash", "Binds a hop to the exact previous slip by hashing it — so hops can't be spliced across chains."],
    ["ES256 / P-256", "ECDSA on the NIST P-256 curve with SHA-256 — the only signature algorithm AP2 mandates accept here."],
    ["mandate", "The permission slip itself: open (a budget + limits) or closed (a concrete payment)."],
    ["receipt reference", "The hash of the final slip — a tamper-proof pointer for receipts and disputes (AUTH-17)."],
  ];
  const gloss = $("#glossary");
  for (const [t, d] of TERMS) {
    const dl = el("dl", "term");
    dl.appendChild(el("dt", null, t));
    dl.appendChild(el("dd", null, d));
    gloss.appendChild(dl);
  }

  /* ---------- live HTTP runner ---------- */
  const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  const targetInput = $("#targetUrl");
  const runBtn = $("#runBtn");
  const runnerOut = $("#runnerOut");
  const httpBase = location.origin && location.origin.startsWith("http") ? location.origin : "https://ap2conformance.dev";
  targetInput.value = httpBase + "/api/verify-chain";

  function renderLive(rep) {
    const pass = rep.conformant;
    const rows = rep.results
      .map(
        (r) =>
          `<div class="vec-row" title="${esc(r.detail || "")}"><span class="vmark${r.passed ? "" : " fail"}">${r.passed ? "✓" : "✗"}</span><span class="vname">${esc(r.name)}</span><span class="vec-tag ${r.profile}">${r.profile}</span></div>`,
      )
      .join("");
    runnerOut.innerHTML =
      `<div class="runner-head ${pass ? "pass" : "fail"}"><span class="rh-verdict">${pass ? "✅ chain conformant" : "❌ chain failures"}</span>` +
      `<span class="rh-counts">${rep.core.passed}/${rep.core.total} core · ${rep.hardening.passed}/${rep.hardening.total} hardening</span>` +
      `<span class="rh-target">${esc(rep.target)}</span></div>` +
      `<div class="runner-grid">${rows}</div>` +
      `<p class="runner-note">${esc(rep.note || "")}</p>`;
  }

  async function runLive() {
    const url = (targetInput.value || "").trim();
    if (!url) return;
    runBtn.disabled = true;
    const label = runBtn.textContent;
    runBtn.textContent = "running…";
    runnerOut.hidden = false;
    runnerOut.innerHTML = `<div class="runner-status">contacting <code>${esc(url)}</code> …</div>`;
    try {
      const r = await fetch(`/api/conform?target=${encodeURIComponent(url)}`, { headers: { accept: "application/json" } });
      if (!r.ok) throw new Error("runner returned HTTP " + r.status);
      renderLive(await r.json());
    } catch (e) {
      runnerOut.innerHTML =
        `<div class="runner-status err">The live runner is a serverless route — it only exists on the deployed site.<br>Deploy to Vercel, or run <code>vercel dev</code> locally, then Run.<br><span class="dim">(${esc((e && e.message) || e)})</span></div>`;
    } finally {
      runBtn.disabled = false;
      runBtn.textContent = label;
    }
  }
  runBtn.addEventListener("click", runLive);

  /* ---------- scroll reveal ---------- */
  const revealIO = new IntersectionObserver((entries) => {
    entries.forEach((e) => { if (e.isIntersecting) { e.target.classList.add("in"); revealIO.unobserve(e.target); } });
  }, { threshold: 0.12 });
  document.querySelectorAll(".reveal").forEach((n) => revealIO.observe(n));
})();
