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
// Detail-mode caps. Higher than compact so a user who explicitly asked
// for details actually sees the long tail (per-hop relays, per-sig DKIM
// entries, per-flag integrity rows) — but still bounded so a malicious
// mail with thousands of synthetic hops can't blow up the panel.
const MAX_DETAIL_ROWS_PER_GROUP = 32;

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
    // Surface the MTA that claimed these verdicts. Without it, a quick
    // glance can't tell whether `DKIM=fail` came from the user's real
    // mailbox provider or an attacker MTA that prepended an
    // Authentication-Results header. The popup + inline-detail mode
    // already show this; compact mode used to omit it.
    if (v.server && parts.length) {
      parts.push("via " + shortText(v.server, 80));
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
// Relay-path direction setting — needed by detail-mode renderers. The
// compact summary doesn't use it.
const DEFAULT_RELAY_DIRECTION = Object.freeze({ relayPathDirection: "originFirst" });
const DEFAULT_DISPLAY = Object.freeze({ displayMode: "popup" });
const DEFAULT_THEME = Object.freeze({ theme: "auto" });
const DEFAULT_INLINE_DETAILS = Object.freeze({ inlineDetails: false });

// Cached so buildPanel() can run synchronously — we hydrate this once on
// script load and keep it up-to-date via storage.onChanged. That avoids
// the race where two quick mount() calls would both await storage and
// could interleave their insertBefore with each other.
let CACHED_PREFS = { ...DEFAULT_SHOW };
let CACHED_DISPLAY_MODE = DEFAULT_DISPLAY.displayMode;
let CACHED_THEME = DEFAULT_THEME.theme;
let CACHED_INLINE_DETAILS = DEFAULT_INLINE_DETAILS.inlineDetails;
let DISPLAY_MODE_READY = false;

// Per-mount override: tri-state. `null` means "honour the persisted
// inlineDetails setting"; `true`/`false` is the user's per-panel choice
// after clicking the Details button. Reset on every mount() so a new
// message starts in the default state defined by the setting.
let SESSION_DETAILS_OVERRIDE = null;
function shouldShowDetails() {
  return SESSION_DETAILS_OVERRIDE != null
    ? SESSION_DETAILS_OVERRIDE
    : CACHED_INLINE_DETAILS;
}

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
      ...DEFAULT_INLINE_DETAILS,
      ...DEFAULT_RELAY_DIRECTION,
    });
    CACHED_PREFS = {
      ...DEFAULT_SHOW,
      ...DEFAULT_RELAY_DIRECTION,
      ...s,
    };
    CACHED_DISPLAY_MODE = normalizeDisplayMode(s.displayMode);
    CACHED_THEME = normalizeTheme(s.theme);
    CACHED_INLINE_DETAILS = s.inlineDetails === true;
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
    if ("relayPathDirection" in changes) {
      const nv = changes.relayPathDirection.newValue;
      CACHED_PREFS.relayPathDirection =
        (nv === "originFirst" || nv === "receiverFirst")
          ? nv : DEFAULT_RELAY_DIRECTION.relayPathDirection;
      dirty = true;
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
    let inlineDetailsChanged = false;
    if ("inlineDetails" in changes) {
      CACHED_INLINE_DETAILS = changes.inlineDetails.newValue === true;
      // Setting flip clears the per-mount override so the new default
      // wins for the currently-visible panel too.
      SESSION_DETAILS_OVERRIDE = null;
      inlineDetailsChanged = true;
    }
    if (modeChanged && !bodyInlineEnabled()) {
      removePanel();
      return;
    }
    if ((dirty && document.getElementById(ROOT_ID)) ||
        (modeChanged && bodyInlineEnabled()) ||
        (inlineDetailsChanged && document.getElementById(ROOT_ID))) {
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

  // Details toggle — wired only when we actually have a summary to expand.
  // The label flips between "Details" and "Kompakt" so the button always
  // announces the action it will take, not the current state.
  const detailsOn = shouldShowDetails();
  if (summary && !summary.error) {
    const detailsBtn = el("button", "mleak-btn mleak-btn-details",
      t(detailsOn ? "inlineCompactButton" : "inlineDetailsButton"));
    detailsBtn.type = "button";
    detailsBtn.setAttribute("aria-pressed", detailsOn ? "true" : "false");
    detailsBtn.addEventListener("click", () => {
      // Toggle the per-mount override. mount() preserves the override —
      // only requestAndMount() (new-mail flow) clears it — so the user's
      // explicit choice persists across this re-render but resets when a
      // different mail is displayed.
      SESSION_DETAILS_OVERRIDE = !shouldShowDetails();
      mount(summary);
    });
    head.append(detailsBtn);
  }

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

  // Compact one-line grid — always rendered. Details mode appends a
  // second block below with the full per-hop / per-finding breakdown.
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

  const anyCompact = mua || stack || leaks || auth || dkim || integrity;
  if (!anyCompact && !detailsOn) {
    root.append(el("div", "mleak-empty", t("noSignals")));
  } else if (anyCompact) {
    root.append(grid);
  }

  if (detailsOn) {
    const details = buildDetails(summary, prefs);
    if (details) root.append(details);
  }
  return root;
}

// ---------- detail-mode renderers -----------------------------------------
//
// These mirror the popup's structured cards but render into the inline
// panel's own DOM/CSS. Every value is read off the summary object the
// background already produced, so the detail view never re-runs the
// detector — it just displays more of the same data.

function detailRow(grid, k, v, cls) {
  if (v == null || v === "") return;
  if (typeof v === "string") {
    grid.append(el("div", "mleak-k", k));
    grid.append(el("div", "mleak-v" + (cls ? " " + cls : ""), v));
    return;
  }
  // Node / element — drop straight into the value column.
  grid.append(el("div", "mleak-k", k));
  const vDiv = el("div", "mleak-v" + (cls ? " " + cls : ""));
  vDiv.append(v);
  grid.append(vDiv);
}

function detailGroupHeader(parent, label) {
  const h = el("div", "mleak-detail-group", label);
  parent.append(h);
}

function detailBadge(level) {
  const lvl = level === "high" || level === "medium" || level === "low"
    ? level : "medium";
  const b = el("span", "mleak-badge mleak-badge-" + lvl, lvl);
  return b;
}

function hostIpLabel(node) {
  if (!node || typeof node !== "object") return "?";
  const h = node.by_host || node.host || null;
  const ip = node.by_ip || node.ip || null;
  if (h && ip) return `${shortText(h, 80)} (${shortText(ip, 60)})`;
  return shortText(h || ip || "?", 120);
}

function buildDetailsMua(grid, summary) {
  const sigs = asArray(summary.mua_signals, MAX_DETAIL_ROWS_PER_GROUP);
  if (!sigs.length) return false;
  for (const s of sigs) {
    if (!s || !s.label) continue;
    const wrap = el("div", "mleak-multi");
    wrap.append(detailBadge(s.conf));
    wrap.append(el("span", "mleak-detail-src",
      "← " + shortText(s.src || "?", 60)));
    detailRow(grid, shortText(s.label, 120), wrap);
  }
  return true;
}

function buildDetailsStack(grid, summary, settings) {
  let any = false;
  const stacks = asArray(summary.server_stacks, MAX_DETAIL_ROWS_PER_GROUP);
  if (stacks.length) {
    detailRow(grid, "Stacks", stacks.map(v => shortText(v, 80)).join(" + "));
    any = true;
  }
  if (summary.tenant_id) {
    detailRow(grid, "M365 Tenant", shortText(summary.tenant_id, 120), "warn");
    any = true;
  }
  if (summary.leaks && summary.leaks.m365_datacenter) {
    detailRow(grid, "DC Region",
      shortText(summary.leaks.m365_datacenter, 120));
    any = true;
  }
  if (summary.delivered_to) {
    detailRow(grid, "Delivered-To", shortText(summary.delivered_to, 120));
    any = true;
  }
  if (summary.return_path) {
    detailRow(grid, "Return-Path", shortText(summary.return_path, 120));
    any = true;
  }
  if (summary.hop_count != null) {
    detailRow(grid, "Hops", String(summary.hop_count));
    any = true;
    const rawHops = asArray(summary.relay_hops, MAX_DETAIL_ROWS_PER_GROUP);
    if (rawHops.length) {
      const direction = settings && settings.relayPathDirection === "receiverFirst"
        ? "receiverFirst" : "originFirst";
      const hops = direction === "originFirst" ? rawHops.slice().reverse() : rawHops;
      const richSchema = typeof hops[0] === "object";
      const wrap = el("div", "mleak-detail-hops");
      if (direction === "originFirst" && summary.relay_origin
          && (summary.relay_origin.host || summary.relay_origin.ip)) {
        wrap.append(el("div", "mleak-detail-hop",
          "↗ origin: " + hostIpLabel(summary.relay_origin)));
      }
      for (let i = 0; i < hops.length; i++) {
        const line = el("div", "mleak-detail-hop",
          (i === 0 ? "· " : "→ ")
          + (richSchema ? hostIpLabel(hops[i]) : shortText(hops[i], 120)));
        wrap.append(line);
      }
      detailRow(grid, "Relay path", wrap);
    }
  }
  if (summary.chronology_anomaly) {
    detailRow(grid, "Chronology",
      shortText(summary.chronology_anomaly, 200), "warn");
    any = true;
  }
  const lists = asArray(summary.mailing_lists, MAX_DETAIL_ROWS_PER_GROUP);
  for (const ml of lists) {
    if (!ml || !ml.value) continue;
    const markers = ml.leaks && Array.isArray(ml.leaks.markers) ? ml.leaks.markers : [];
    const src = markers.length
      ? " via " + markers.slice(0, 4).map(m => shortText(m.header || "?", 40)).join(", ")
      : "";
    detailRow(grid, "Mailing List", shortText(ml.value, 120) + src);
    any = true;
  }
  if (summary.header_order && summary.header_order.value) {
    detailRow(grid, "Header Order",
      shortText(summary.header_order.value, 200));
    any = true;
  }
  return any;
}

function buildDetailsLeaks(grid, summary) {
  let any = false;
  const intHops = asArray(summary.internal_hostname_hops,
                          MAX_DETAIL_ROWS_PER_GROUP);
  if (intHops.length) {
    for (const h of intHops) {
      if (!h || !h.host) continue;
      const ctx = [];
      if (h.by)   ctx.push("at "   + shortText(h.by, 80));
      if (h.from && h.from !== h.by) ctx.push("from " + shortText(h.from, 80));
      detailRow(grid, "Internal Host",
        shortText(h.host, 120) + (ctx.length ? "  " + ctx.join(" · ") : ""),
        "bad");
      any = true;
    }
  } else if (summary.internal_hostname_leak) {
    detailRow(grid, "Internal Host",
      shortText(summary.internal_hostname_leak, 120), "bad");
    any = true;
  }
  const privHops = asArray(summary.private_ip_hops, MAX_DETAIL_ROWS_PER_GROUP);
  if (privHops.length) {
    for (const h of privHops) {
      if (!h || !h.ip) continue;
      const ctx = [];
      if (h.by)   ctx.push("at "   + shortText(h.by, 80));
      if (h.from && h.from !== h.by) ctx.push("from " + shortText(h.from, 80));
      detailRow(grid, "Private IP",
        shortText(h.ip, 80) + (ctx.length ? "  " + ctx.join(" · ") : ""),
        "bad");
      any = true;
    }
  } else if (summary.private_ip_leak) {
    detailRow(grid, "Private IP",
      shortText(summary.private_ip_leak, 120), "bad");
    any = true;
  }
  if (summary.leaks && summary.leaks.hostname_leak) {
    detailRow(grid, "Device Hostname",
      shortText(summary.leaks.hostname_leak, 120), "warn");
    any = true;
  }
  const senderIps = asArray(summary.sender_ips, MAX_DETAIL_ROWS_PER_GROUP);
  for (const hit of senderIps) {
    if (!hit || !hit.value) continue;
    const leaks = hit.leaks || {};
    const label = leaks.header
      ? shortText(hit.value, 80) + " (" + shortText(leaks.header, 60) + ")"
      : shortText(hit.value, 120);
    detailRow(grid, "Sender IP", label, leaks.private ? "bad" : "warn");
    any = true;
  }
  if (summary.leaks && summary.leaks.mid) {
    const mid = summary.leaks.mid;
    if (mid.datacenter_hint && mid.datacenter_code) {
      detailRow(grid, "M365 DC",
        shortText(mid.datacenter_code, 60) + " (" +
        shortText(mid.datacenter_hint, 60) + ")");
      any = true;
    }
    if (mid.internal_hostname && !summary.internal_hostname_leak) {
      detailRow(grid, "Exchange Host",
        shortText(mid.internal_hostname, 120), "warn");
      any = true;
    }
  }
  return any;
}

function buildDetailsAuth(grid, summary) {
  let any = false;
  const verdicts = summary.auth_verdicts;
  if (verdicts && typeof verdicts === "object") {
    for (const test of ["spf", "dkim", "dmarc", "arc", "bimi"]) {
      const r = verdicts[test];
      if (!r) continue;
      const cls = (r === "pass" || r === "bestguesspass") ? null
                : (r === "fail" ? "bad" : "warn");
      detailRow(grid, test.toUpperCase(), shortText(String(r), 30), cls);
      any = true;
    }
    if (verdicts.server) {
      detailRow(grid, "Auth Server", shortText(verdicts.server, 120));
      any = true;
    }
  }
  const sigs = asArray(summary.dkim_signatures, MAX_DETAIL_ROWS_PER_GROUP);
  for (const sig of sigs) {
    if (!sig) continue;
    let label = shortText(sig.domain || "?", 80) + "/" +
                shortText(sig.selector || "?", 60);
    if (sig.vendor_hint) label += "  (" + shortText(sig.vendor_hint, 60) + ")";
    detailRow(grid, "DKIM", label);
    any = true;
  }
  const crypto = asArray(summary.crypto, MAX_DETAIL_ROWS_PER_GROUP);
  for (const c of crypto) {
    if (!c || !c.kind) continue;
    detailRow(grid,
      shortText(String(c.kind).replace(/_/g, " "), 60),
      shortText(c.value || "?", 120));
    any = true;
  }
  return any;
}

function buildDetailsIntegrity(grid, summary) {
  const flags = asArray(summary.integrity_flags, MAX_DETAIL_ROWS_PER_GROUP);
  if (!flags.length) return false;
  for (const f of flags) {
    if (!f || !f.kind) continue;
    detailRow(grid,
      shortText(String(f.kind).replace(/_/g, " "), 60),
      shortText(f.value || "?", 200), "warn");
  }
  return true;
}

function buildDetailsDate(grid, summary) {
  const d = summary.date;
  if (!d || !d.raw) return false;
  detailRow(grid, "Raw", shortText(d.raw, 200));
  if (d.parsed) {
    const pretty = String(d.parsed).replace("T", " ")
                                   .replace(/\.\d{3}Z$/, "")
                                   .replace(/Z$/, "") + " UTC";
    detailRow(grid, "UTC", pretty);
  }
  if (typeof d.tz_offset_minutes === "number" &&
      Number.isFinite(d.tz_offset_minutes)) {
    const mins = d.tz_offset_minutes;
    const sign = mins >= 0 ? "+" : "-";
    const abs = Math.abs(mins);
    const tz = "UTC" + sign +
               String(Math.floor(abs / 60)).padStart(2, "0") + ":" +
               String(abs % 60).padStart(2, "0");
    detailRow(grid, "Timezone", tz);
  }
  return true;
}

function buildDetailsMime(grid, summary) {
  let any = false;
  if (summary.mime_structure) {
    detailRow(grid, "Structure", shortText(summary.mime_structure, 300));
    any = true;
  }
  const boundaries = asArray(summary.mime_boundaries, MAX_DETAIL_ROWS_PER_GROUP);
  for (const b of boundaries) {
    if (!b) continue;
    const tail = b.leaks && b.leaks.boundary
      ? "  [" + shortText(b.leaks.boundary, 60) + "]"
      : "";
    detailRow(grid, "boundary",
      shortText(b.value || "?", 120) + tail);
    any = true;
  }
  return any;
}

function buildDetails(summary, prefs) {
  const wrap = el("div", "mleak-details");
  // settings.relayPathDirection cached via storage.get on each requestAndMount?
  // We don't have direct access here; the inline panel honours whatever it
  // last cached. Read it lazily off CACHED_PREFS so a setting flip via
  // storage.onChanged would already have rebuilt CACHED_PREFS.
  const settings = { relayPathDirection: CACHED_PREFS.relayPathDirection };

  const groups = [
    ["MUA",        prefs.showMua,       buildDetailsMua],
    ["Stack",      prefs.showStack,     (g, s) => buildDetailsStack(g, s, settings)],
    ["Leaks",      prefs.showLeaks,     buildDetailsLeaks],
    ["Auth",       prefs.showAuth,      buildDetailsAuth],
    ["Integrity",  prefs.showIntegrity, buildDetailsIntegrity],
    ["Date",       prefs.showDate,      buildDetailsDate],
    ["MIME",       prefs.showMime,      buildDetailsMime],
  ];

  let renderedAnyGroup = false;
  for (const [label, pref, builder] of groups) {
    if (pref === false) continue;
    const grid = el("div", "mleak-grid mleak-detail-grid");
    const populated = builder(grid, summary);
    if (!populated) continue;
    detailGroupHeader(wrap, label);
    wrap.append(grid);
    renderedAnyGroup = true;
  }

  if (!renderedAnyGroup) {
    wrap.append(el("div", "mleak-empty", t("noSignals")));
  }
  return wrap;
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
  // New-mail entry point: clear any prior Details-button override so the
  // freshly-displayed mail starts from the persisted `inlineDetails`
  // default. mount() itself doesn't reset, so toggle-button re-renders
  // (which call mount() directly) preserve the user's choice.
  SESSION_DETAILS_OVERRIDE = null;
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
