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
//   - On load, check storage.displayMode. Only bodyInline fetches analysis
//     and renders the panel; popup/headerInline modes stay inert.
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
const MAX_INLINE_TEXT = 500;
const MAX_INLINE_ITEMS = 8;

// --- mleak-family inline panel protocol v1 ---------------------------------
// Both `mleak` and `mleak-files` (and any future mleak-family tool) inject
// inline panels at the top of the message-display body. Without coordination,
// whichever script's mount() runs last ends up on top — and which one runs
// last depends on Thunderbird's ordering of messageDisplayed listeners, which
// is non-deterministic. We agree on a small DOM convention to bring it under
// control:
//
//   panel.classList                ⊇ "mleak-family-panel"
//   panel.dataset.mleakId          one of "mleak" | "mleak-files" | …
//   panel.dataset.mleakOrder       integer string, ascending = top
//   panel.dataset.mleakProtocol    protocol version string, e.g. "1"
//
// Each extension ships its own copy of composeMleakFamily(); both running on
// the same DOM is safe because the function is idempotent (no-op when already
// in target order). A MutationObserver on document.body catches the case
// where a sibling extension's panel arrives after ours.
//
// We only coordinate with siblings that advertise the SAME protocol version.
// A sibling that ships a future incompatible variant (different sort
// direction, different tiebreak, etc.) won't carry "1" and will therefore be
// invisible to our compositor — we leave its panel untouched and only sort
// our own. This prevents the two MutationObservers from ping-ponging when
// they disagree on order.
const MLEAK_FAMILY_ID = "mleak";
const MLEAK_FAMILY_ORDER = 100;
const MLEAK_FAMILY_PROTOCOL = "1";

function composeMleakFamily() {
  const body = document.body;
  if (!body) return;
  const panels = Array.from(body.children).filter(
    el => el.nodeType === 1
      && el.hasAttribute("data-mleak-order")
      && el.dataset.mleakProtocol === MLEAK_FAMILY_PROTOCOL);
  if (panels.length < 2) return;
  const sorted = panels.slice().sort((a, b) => {
    const ao = Number(a.dataset.mleakOrder);
    const bo = Number(b.dataset.mleakOrder);
    const aOk = Number.isFinite(ao);
    const bOk = Number.isFinite(bo);
    if (aOk && bOk && ao !== bo) return ao - bo;
    if (aOk !== bOk) return aOk ? -1 : 1;
    return (a.dataset.mleakId || "").localeCompare(b.dataset.mleakId || "");
  });
  for (let i = 0; i < panels.length; i++) {
    if (panels[i] !== sorted[i]) {
      // Reinsert sorted panels at the top of body, preserving relative order
      // of any non-family siblings further down.
      for (let j = sorted.length - 1; j >= 0; j--) {
        body.insertBefore(sorted[j], body.firstChild);
      }
      return;
    }
  }
}

let mleakFamilyObserver = null;
function watchMleakFamily() {
  if (mleakFamilyObserver) return;
  if (!document.body) {
    document.addEventListener("DOMContentLoaded", watchMleakFamily, { once: true });
    return;
  }
  mleakFamilyObserver = new MutationObserver(composeMleakFamily);
  mleakFamilyObserver.observe(document.body, { childList: true });
}
watchMleakFamily();
// --- end mleak-family protocol v1 ------------------------------------------

function shortText(value, max = MAX_INLINE_TEXT) {
  const s = String(value == null ? "" : value);
  return s.length > max ? s.slice(0, max) + "...[truncated]" : s;
}

function asArray(value, max = MAX_INLINE_ITEMS) {
  return Array.isArray(value) ? value.slice(0, max) : [];
}

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
  const safeArgs = args.slice(0, MAX_INLINE_ITEMS).map(a => {
    if (a == null) return String(a);
    if (typeof a === "string") return shortText(a);
    if (typeof a === "number" || typeof a === "boolean") return a;
    if (a && typeof a === "object" && typeof a.message === "string") {
      return shortText(a.message);
    }
    return `[${Array.isArray(a) ? "Array" : "Object"}]`;
  });
  const line = "[mleak:inline] " + safeArgs.map(v => shortText(v)).join(" ");
  if (level === "error") console.error(line);
  else if (level === "warn") console.warn(line);
  else console.log(line);
  try {
    // Swallow both sync throws (channel gone) and async rejections so a
    // background restart in the middle of a frame's lifetime doesn't
    // spam console with "Receiving end does not exist" warnings.
    messenger.runtime.sendMessage({
      type: "debug:log", level, where: "inline", args: safeArgs,
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
  const sigs = asArray(s.mua_signals);
  if (!sigs.length) return null;
  // Collapse identical labels (UA and MID often agree)
  const seen = new Set();
  const labels = [];
  for (const sig of sigs) {
    if (!sig.label || seen.has(sig.label)) continue;
    seen.add(sig.label);
      labels.push(shortText(sig.label, 120));
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
  const crypto = asArray(s.crypto);
  for (const c of crypto) {
    if (c.kind === "mime_crypto") { parts.push(shortText(c.value, 120)); break; }
  }
  if (crypto.some(c => c.kind === "autocrypt")) parts.push("Autocrypt");
  return parts.length ? { text: parts.join(" · "), cls: worst === "ok" ? null : worst } : null;
}

function formatLeaks(s) {
  const bits = [];
  if (s.internal_hostname_leak) bits.push(shortText(s.internal_hostname_leak, 120));
  if (s.private_ip_leak) bits.push(shortText(s.private_ip_leak, 120));
  if (s.leaks && s.leaks.hostname_leak) bits.push(shortText(s.leaks.hostname_leak, 120));
  if (Array.isArray(s.sender_ips)) {
    for (const hit of asArray(s.sender_ips)) {
      if (!hit.value) continue;
      const hdr = hit.leaks && hit.leaks.header ? ` ${shortText(hit.leaks.header, 80)}` : "";
      bits.push(`sender ${shortText(hit.value, 120)}${hdr}`);
    }
  }
  return bits.length ? bits.join(" · ") : null;
}

function formatStack(s) {
  const bits = [];
  const serverStacks = asArray(s.server_stacks);
  if (serverStacks.length)
    bits.push(serverStacks.map(v => shortText(v, 80)).join(" + "));
  if (s.tenant_id) bits.push(`tenant ${shortText(s.tenant_id, 13)}...`);
  if (s.leaks && s.leaks.m365_datacenter) bits.push(shortText(s.leaks.m365_datacenter, 120));
  if (s.hop_count != null) bits.push(`${s.hop_count} hops`);
  if (s.chronology_anomaly) bits.push(`chronology ${shortText(s.chronology_anomaly, 120)}`);
  if (Array.isArray(s.mailing_lists) && s.mailing_lists.length) {
    bits.push(`list ${asArray(s.mailing_lists).map(ml => shortText(ml.value, 80)).join("+")}`);
  }
  return bits.length ? bits.join(" · ") : null;
}

function formatDkim(s) {
  const sigs = asArray(s.dkim_signatures);
  if (!sigs.length) return null;
  return sigs.map(sig => {
    let label = `${shortText(sig.domain || "?", 120)}/${shortText(sig.selector || "?", 120)}`;
    if (sig.vendor_hint) label += ` (${shortText(sig.vendor_hint, 120)})`;
    return label;
  }).join(" · ");
}

function formatIntegrity(s) {
  const flags = asArray(s.integrity_flags);
  if (!flags.length) return null;
  // Just count kinds and show up to 2 labels
  const names = flags.map(f => shortText(f.kind, 80).replace(/_/g, " "));
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
const DEFAULT_DISPLAY = Object.freeze({ displayMode: "popup" });
const DEFAULT_THEME = Object.freeze({ theme: "auto" });

// Cached so buildPanel() can run synchronously — we hydrate this once on
// script load and keep it up-to-date via storage.onChanged. That avoids
// the race where two quick mount() calls would both await storage and
// could interleave their insertBefore with each other.
let CACHED_PREFS = { ...DEFAULT_SHOW };
let CACHED_DISPLAY_MODE = DEFAULT_DISPLAY.displayMode;
let CACHED_THEME = DEFAULT_THEME.theme;
let DISPLAY_MODE_READY = false;

function normalizeDisplayMode(mode) {
  return mode === "bodyInline" || mode === "headerInline" ? mode : "popup";
}

function normalizeTheme(theme) {
  return theme === "dark" || theme === "light" ? theme : "auto";
}

function bodyInlineEnabled() {
  return CACHED_DISPLAY_MODE === "bodyInline";
}

async function ensureDisplayMode() {
  if (DISPLAY_MODE_READY) return CACHED_DISPLAY_MODE;
  try {
    const api = (typeof messenger !== "undefined" ? messenger : browser);
    const s = await api.storage.local.get(DEFAULT_DISPLAY);
    CACHED_DISPLAY_MODE = normalizeDisplayMode(s.displayMode);
  } catch (_) {
    CACHED_DISPLAY_MODE = DEFAULT_DISPLAY.displayMode;
  }
  DISPLAY_MODE_READY = true;
  return CACHED_DISPLAY_MODE;
}

(async () => {
  try {
    const api = (typeof messenger !== "undefined" ? messenger : browser);
    const s = await api.storage.local.get({
      ...DEFAULT_SHOW,
      ...DEFAULT_DISPLAY,
      ...DEFAULT_THEME,
    });
    CACHED_PREFS = { ...DEFAULT_SHOW, ...s };
    CACHED_DISPLAY_MODE = normalizeDisplayMode(s.displayMode);
    CACHED_THEME = normalizeTheme(s.theme);
    DISPLAY_MODE_READY = true;
    // Re-render the current panel with fresh prefs if one is already up.
    const existing = document.getElementById(ROOT_ID);
    if (bodyInlineEnabled()) {
      if (existing) requestAndMount();
    } else {
      removePanel();
    }
  } catch (_) { /* storage unavailable; keep defaults */ }
})();

try {
  const api = (typeof messenger !== "undefined" ? messenger : browser);
  api.storage.onChanged.addListener((changes, area) => {
    if (area !== "local") return;
    let dirty = false;
    let modeChanged = false;
    for (const k of Object.keys(DEFAULT_SHOW)) {
      if (k in changes) {
        CACHED_PREFS[k] = changes[k].newValue ?? DEFAULT_SHOW[k];
        dirty = true;
      }
    }
    if ("displayMode" in changes) {
      CACHED_DISPLAY_MODE = normalizeDisplayMode(changes.displayMode.newValue);
      DISPLAY_MODE_READY = true;
      modeChanged = true;
    }
    if ("theme" in changes) {
      CACHED_THEME = normalizeTheme(changes.theme.newValue);
      const existing = document.getElementById(ROOT_ID);
      if (existing) existing.dataset.theme = CACHED_THEME;
    }
    if (modeChanged && !bodyInlineEnabled()) {
      removePanel();
      return;
    }
    if ((dirty && document.getElementById(ROOT_ID)) ||
        (modeChanged && bodyInlineEnabled())) {
      requestAndMount();
    }
  });
} catch (_) { /* no storage API; stuck with initial defaults */ }

function buildPanel(summary, prefs) {
  summary = summary && typeof summary === "object" ? summary : {};
  prefs = prefs || DEFAULT_SHOW;
  const root = el("div");
  root.id = ROOT_ID;
  root.classList.add("mleak-family-panel");
  root.dataset.mleakId = MLEAK_FAMILY_ID;
  root.dataset.mleakOrder = String(MLEAK_FAMILY_ORDER);
  root.dataset.mleakProtocol = MLEAK_FAMILY_PROTOCOL;
  root.dataset.theme = CACHED_THEME;

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
  composeMleakFamily();
}

async function mountIfEnabled(summary) {
  const mode = await ensureDisplayMode();
  if (mode !== "bodyInline") {
    removePanel();
    rlog("info", "bodyInline disabled; panel not mounted");
    return;
  }
  mount(summary);
}

async function togglePanel() {
  const mode = await ensureDisplayMode();
  if (mode !== "bodyInline") {
    removePanel();
    return;
  }
  const existing = document.getElementById(ROOT_ID);
  if (existing) { existing.remove(); return; }
  // No panel currently — ask background for latest result and render it.
  requestAndMount();
}

async function requestAndMount() {
  rlog("info", "requestAndMount");
  const mode = await ensureDisplayMode();
  if (mode !== "bodyInline") {
    removePanel();
    rlog("info", "bodyInline disabled; skipping analysis request");
    return;
  }
  try {
    const res = await messenger.runtime.sendMessage({ type: "current" });
    rlog("info", "got result", res && (res.summary
      ? `summary keys: ${Object.keys(res.summary).length}` : `[${typeof res}]`));
    if (res) await mountIfEnabled(res.summary || res);
  } catch (e) {
    rlog("error", "sendMessage failed:", e && e.message || e);
    await mountIfEnabled({ error: String(e && e.message || e) });
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
  else if (msg.action === "show" && msg.summary) mountIfEnabled(msg.summary);
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
