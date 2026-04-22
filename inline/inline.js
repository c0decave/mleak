/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * SPDX-License-Identifier: MPL-2.0
 */
// Message-display script: renders a compact mleak panel at the top of the
// message body. Runs inside the message-display frame (isolated from the
// page script), so DOM access is safe.
//
// Lifecycle:
//   - On load, fetch analysis for the currently displayed message from the
//     background page and render the panel.
//   - Background also pushes "result"/"toggle" messages (e.g. when the
//     toolbar icon is clicked while inline mode is active).
//   - Panel removes itself on unload (new message → fresh frame load).

"use strict";

(() => {

// Idempotency guard. Thunderbird runs messageDisplayScripts exactly once
// per frame, but background.js also calls tabs.executeScript into already-
// open message frames when inline-mode is (re-)enabled. A subsequent
// enable→disable→enable cycle on the same open mail would therefore inject
// inline.js twice into the same frame, piling up runtime.onMessage
// listeners. Skip the second run — the first instance is already wired up.
if (globalThis.__mleakInlineInited) return;
globalThis.__mleakInlineInited = true;

const ROOT_ID = "mleak-inline-root";

// Minimal inline i18n — message-display scripts run in a frame where the
// extension's messenger.i18n is available but lib/i18n.js isn't loaded.
function t(key) {
  try {
    const api = (typeof messenger !== "undefined" ? messenger : browser);
    return api.i18n.getMessage(key) || key;
  } catch (_) { return key; }
}

// Light-weight remote log. Mirrors to the page console + forwards to the
// background, which decides (based on debugLog setting) whether to persist.
function rlog(level, ...args) {
  const line = "[mleak:inline] " + args.map(a => {
    if (a == null) return String(a);
    if (typeof a === "string") return a;
    try { return JSON.stringify(a); } catch (_) { return String(a); }
  }).join(" ");
  if (level === "error") console.error(line);
  else if (level === "warn") console.warn(line);
  else console.log(line);
  try {
    // Swallow both sync throws (channel gone) and async rejections so a
    // background restart in the middle of a frame's lifetime doesn't
    // spam console with "Receiving end does not exist" warnings.
    messenger.runtime.sendMessage({
      type: "debug:log", level, where: "inline", args,
    }).catch(() => {});
  } catch (_) { /* channel gone */ }
}

function escapeText(s) {
  return String(s == null ? "" : s);
}

function el(tag, cls, textOrChildren) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (textOrChildren == null) return e;
  if (Array.isArray(textOrChildren)) {
    for (const c of textOrChildren) if (c != null) e.append(c);
  } else if (typeof textOrChildren === "object" && textOrChildren instanceof Node) {
    e.append(textOrChildren);
  } else {
    e.textContent = escapeText(textOrChildren);
  }
  return e;
}

function row(grid, k, v, cls) {
  grid.append(el("div", "mleak-k", k));
  const vDiv = el("div", "mleak-v" + (cls ? " " + cls : ""), v);
  grid.append(vDiv);
}

function formatMua(s) {
  const sigs = s.mua_signals || [];
  if (!sigs.length) return null;
  // Collapse identical labels (UA and MID often agree)
  const seen = new Set();
  const labels = [];
  for (const sig of sigs) {
    if (!sig.label || seen.has(sig.label)) continue;
    seen.add(sig.label);
    labels.push(sig.label);
  }
  return labels.join("  ·  ");
}

function formatAuth(s) {
  const v = s.auth_verdicts;
  const parts = [];
  let worst = "ok";
  if (v) {
    for (const test of ["spf", "dkim", "dmarc"]) {
      const r = v[test];
      if (!r) continue;
      parts.push(`${test.toUpperCase()}=${r}`);
      if (r === "fail") worst = "bad";
      else if (r !== "pass" && r !== "bestguesspass" && worst === "ok") worst = "warn";
    }
  }
  // Append a compact crypto marker so inline readers see at a glance that
  // the mail is PGP/SMIME-signed or encrypted.
  const crypto = Array.isArray(s.crypto) ? s.crypto : [];
  for (const c of crypto) {
    if (c.kind === "mime_crypto") { parts.push(c.value); break; }
  }
  if (crypto.some(c => c.kind === "autocrypt")) parts.push("Autocrypt");
  return parts.length ? { text: parts.join(" · "), cls: worst === "ok" ? null : worst } : null;
}

function formatLeaks(s) {
  const bits = [];
  if (s.internal_hostname_leak) bits.push(s.internal_hostname_leak);
  if (s.private_ip_leak) bits.push(s.private_ip_leak);
  if (s.leaks && s.leaks.hostname_leak) bits.push(s.leaks.hostname_leak);
  return bits.length ? bits.join(" · ") : null;
}

function formatStack(s) {
  const bits = [];
  if (s.server_stacks && s.server_stacks.length)
    bits.push(s.server_stacks.join(" + "));
  if (s.tenant_id) bits.push(`tenant ${s.tenant_id.slice(0, 13)}…`);
  if (s.leaks && s.leaks.m365_datacenter) bits.push(s.leaks.m365_datacenter);
  if (s.hop_count != null) bits.push(`${s.hop_count} hops`);
  return bits.length ? bits.join(" · ") : null;
}

function formatDkim(s) {
  const sigs = s.dkim_signatures || [];
  if (!sigs.length) return null;
  return sigs.map(sig => {
    let label = `${sig.domain || "?"}/${sig.selector || "?"}`;
    if (sig.vendor_hint) label += ` (${sig.vendor_hint})`;
    return label;
  }).join(" · ");
}

function formatIntegrity(s) {
  const flags = s.integrity_flags || [];
  if (!flags.length) return null;
  // Just count kinds and show up to 2 labels
  const names = flags.map(f => f.kind.replace(/_/g, " "));
  const unique = Array.from(new Set(names));
  if (unique.length <= 2) return unique.join(" · ");
  return `${unique.slice(0, 2).join(" · ")} +${unique.length - 2}`;
}

// Default card-visibility when we couldn't reach storage in time (or at
// all — e.g. background briefly down). Matches lib/settings.js DEFAULTS.
const DEFAULT_SHOW = Object.freeze({
  showMua: true, showStack: true, showLeaks: true, showAuth: true,
  showIntegrity: true, showDate: true, showMime: true,
});

// Cached so buildPanel() can run synchronously — we hydrate this once on
// script load and keep it up-to-date via storage.onChanged. That avoids
// the race where two quick mount() calls would both await storage and
// could interleave their insertBefore with each other.
let CACHED_PREFS = { ...DEFAULT_SHOW };

(async () => {
  try {
    const api = (typeof messenger !== "undefined" ? messenger : browser);
    const s = await api.storage.local.get(DEFAULT_SHOW);
    CACHED_PREFS = { ...DEFAULT_SHOW, ...s };
    // Re-render the current panel with fresh prefs if one is already up.
    const existing = document.getElementById(ROOT_ID);
    if (existing) requestAndMount();
  } catch (_) { /* storage unavailable; keep defaults */ }
})();

try {
  const api = (typeof messenger !== "undefined" ? messenger : browser);
  api.storage.onChanged.addListener((changes, area) => {
    if (area !== "local") return;
    let dirty = false;
    for (const k of Object.keys(DEFAULT_SHOW)) {
      if (k in changes) {
        CACHED_PREFS[k] = changes[k].newValue ?? DEFAULT_SHOW[k];
        dirty = true;
      }
    }
    if (dirty && document.getElementById(ROOT_ID)) requestAndMount();
  });
} catch (_) { /* no storage API; stuck with initial defaults */ }

function buildPanel(summary, prefs) {
  prefs = prefs || DEFAULT_SHOW;
  const root = el("div");
  root.id = ROOT_ID;

  const head = el("div", "mleak-head");
  // SVG logo — same envelope + magnifying-glass as icons/logo.svg, built
  // programmatically so we don't need to fetch() the svg file at render time.
  const NS = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(NS, "svg");
  svg.setAttribute("class", "mleak-logo");
  svg.setAttribute("viewBox", "0 0 48 48");
  svg.setAttribute("aria-hidden", "true");

  const svgAttr = (node, attrs) => {
    for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
    return node;
  };

  // Envelope body
  svg.append(svgAttr(document.createElementNS(NS, "rect"), {
    x: "2", y: "10", width: "30", height: "22", rx: "2",
    fill: "none", stroke: "currentColor", "stroke-width": "3",
    "stroke-linejoin": "round",
  }));
  // Envelope flap
  svg.append(svgAttr(document.createElementNS(NS, "path"), {
    d: "M 2 11 L 17 23 L 32 11",
    fill: "none", stroke: "currentColor", "stroke-width": "3",
    "stroke-linecap": "round", "stroke-linejoin": "round",
  }));
  // Magnifying-glass lens
  svg.append(svgAttr(document.createElementNS(NS, "circle"), {
    cx: "35", cy: "35", r: "8",
    fill: "none", stroke: "currentColor", "stroke-width": "3",
  }));
  // Magnifying-glass handle
  svg.append(svgAttr(document.createElementNS(NS, "line"), {
    x1: "40.5", y1: "40.5", x2: "45", y2: "45",
    stroke: "currentColor", "stroke-width": "3.5", "stroke-linecap": "round",
  }));

  head.append(svg, el("span", "mleak-title", "mleak"), el("span", "mleak-spacer"));
  const btn = el("button", "mleak-btn", t("hideButton"));
  btn.type = "button";
  btn.addEventListener("click", () => {
    const r = document.getElementById(ROOT_ID);
    if (r) r.remove();
  });
  head.append(btn);
  root.append(head);

  if (!summary || summary.error) {
    const err = el("div", "mleak-empty",
      summary && summary.error ? String(summary.error) : t("noData"));
    root.append(err);
    return root;
  }

  const grid = el("div", "mleak-grid");
  const mua   = prefs.showMua       !== false ? formatMua(summary)   : null;
  if (mua)   row(grid, "MUA", mua);

  const stack = prefs.showStack     !== false ? formatStack(summary) : null;
  if (stack) row(grid, "Stack", stack);

  const leaks = prefs.showLeaks     !== false ? formatLeaks(summary) : null;
  if (leaks) row(grid, "Leaks", leaks, "bad");

  const auth  = prefs.showAuth      !== false ? formatAuth(summary)  : null;
  if (auth)  row(grid, "Auth", auth.text, auth.cls);

  // DKIM sub-signal folds into the Auth card conceptually; only show when
  // the Auth card is enabled.
  const dkim  = prefs.showAuth      !== false ? formatDkim(summary)  : null;
  if (dkim)  row(grid, "DKIM", dkim);

  const integrity = prefs.showIntegrity !== false ? formatIntegrity(summary) : null;
  if (integrity) row(grid, t("cardIntegrity"), integrity, "warn");

  if (!mua && !stack && !leaks && !auth && !dkim && !integrity) {
    root.append(el("div", "mleak-empty", t("noSignals")));
  } else {
    root.append(grid);
  }
  return root;
}

function removePanel() {
  const existing = document.getElementById(ROOT_ID);
  if (existing) existing.remove();
}

function mount(summary) {
  removePanel();
  const panel = buildPanel(summary, CACHED_PREFS);
  // Inject at the very top of <body>. In Thunderbird's message display
  // iframe, <body> is the rendered email body — prepending puts our panel
  // above the mail content, which is exactly what we want.
  const body = document.body;
  if (!body) return;
  body.insertBefore(panel, body.firstChild);
}

function togglePanel() {
  const existing = document.getElementById(ROOT_ID);
  if (existing) { existing.remove(); return; }
  // No panel currently — ask background for latest result and render it.
  requestAndMount();
}

async function requestAndMount() {
  rlog("info", "requestAndMount @", location.href);
  try {
    const res = await messenger.runtime.sendMessage({ type: "current" });
    rlog("info", "got result", res && (res.summary
      ? `summary keys: ${Object.keys(res.summary).length}` : JSON.stringify(res)));
    if (res) mount(res.summary || res);
  } catch (e) {
    rlog("error", "sendMessage failed:", e && e.message || e);
    mount({ error: String(e && e.message || e) });
  }
}

// Listen for pushes from the background (toolbar-icon toggle; new message
// analyzed; settings-changed clearing etc.)
messenger.runtime.onMessage.addListener((msg) => {
  // Shape guard — symmetric to the one in background.js onMessage. Only
  // our own background talks to us (cross-extension messaging would need
  // onMessageExternal, which we don't expose), but making the type check
  // explicit means a future onMessageExternal addition can't silently
  // hand us a primitive handle.
  if (!msg || typeof msg.type !== "string") return;
  if (msg.type !== "mleak:panel") return;
  if (typeof msg.action !== "string") return;
  if      (msg.action === "toggle") togglePanel();
  else if (msg.action === "hide")   removePanel();
  else if (msg.action === "show" && msg.summary) mount(msg.summary);
  else if (msg.action === "show")   requestAndMount();
});

// Auto-render on load
rlog("info", "inline.js loaded, readyState =", document.readyState);
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", requestAndMount);
} else {
  requestAndMount();
}

})();
